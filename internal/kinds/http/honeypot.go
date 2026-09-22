package http

import (
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/bound"
	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/proxy"
)

// Decoys are the built-in honeypot bodies. Each looks like a real page
// of the named kind to a scanner and contains nothing an operator would
// mind being read.
var decoys = map[string]struct{ contentType, body string }{
	"wp-login": {"text/html; charset=utf-8", `<!DOCTYPE html>
<html lang="en-US"><head><meta charset="UTF-8"><title>Log In &lsaquo; WordPress</title>
<link rel="stylesheet" href="/wp-admin/css/login.min.css"></head>
<body class="login login-action-login wp-core-ui"><div id="login"><h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login" class="input" size="20"></p>
<p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass" class="input" size="20"></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary" value="Log In"><input type="hidden" name="redirect_to" value="/wp-admin/"></p>
</form></div></body></html>
`},
	"env": {"text/plain; charset=utf-8", `APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:ZGVjb3kta2V5LW5vdC1yZWFsLWRvLW5vdC11c2UtMDAwMDA=
APP_DEBUG=false
APP_URL=http://localhost
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=app
DB_USERNAME=app
DB_PASSWORD=decoy-Passw0rd
REDIS_HOST=127.0.0.1
MAIL_MAILER=smtp
AWS_ACCESS_KEY_ID=AKIADECOY000000EXAMPLE
AWS_SECRET_ACCESS_KEY=decoy/secret/not/real/0000000000000000
`},
	"git-config": {"text/plain; charset=utf-8", `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = git@git.example.internal:platform/web.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
`},
	"phpinfo": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>
<div class="center"><table><tr class="h"><td><h1 class="p">PHP Version 7.4.33</h1></td></tr></table>
<table><tr><td class="e">System </td><td class="v">Linux web01 5.4.0-150-generic #167-Ubuntu SMP x86_64 </td></tr>
<tr><td class="e">Server API </td><td class="v">FPM/FastCGI </td></tr>
<tr><td class="e">Loaded Configuration File </td><td class="v">/etc/php/7.4/fpm/php.ini </td></tr>
<tr><td class="e">allow_url_fopen </td><td class="v">On </td></tr><tr><td class="e">display_errors </td><td class="v">Off </td></tr>
</table></div></body></html>
`},
	"admin-login": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Administration</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body><main><h1>Administration</h1><form method="post" action="/admin/login">
<label>User <input name="username" autocomplete="username"></label>
<label>Password <input type="password" name="password" autocomplete="current-password"></label>
<button type="submit">Sign in</button></form></main></body></html>
`},
	"robots": {"text/plain; charset=utf-8", `User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /private/
Disallow: /wp-admin/
Disallow: /.git/
`},
	"phpmyadmin": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>phpMyAdmin</title>
<link rel="stylesheet" href="/themes/pmahomme/css/theme.css"></head>
<body class="loginform"><div class="container"><a href="https://www.phpmyadmin.net/" class="logo">phpMyAdmin</a>
<form method="post" action="index.php" name="login_form" class="login hide js-show">
<fieldset><legend>Log in</legend>
<div class="item"><label for="input_username">Username:</label><input type="text" name="pma_username" id="input_username" value=""></div>
<div class="item"><label for="input_password">Password:</label><input type="password" name="pma_password" id="input_password"></div>
<div class="item"><label for="select_server">Server Choice:</label>
<select name="server" id="select_server"><option value="1">localhost</option></select></div>
</fieldset><fieldset class="tblFooters"><input type="submit" value="Go" id="input_go"></fieldset></form>
<div class="group"><p>phpMyAdmin 4.9.7</p></div></div></body></html>
`},
	"tomcat-manager": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><title>/manager</title>
<style type="text/css">body{font-family:sans-serif;}</style></head>
<body><h1>Tomcat Web Application Manager</h1>
<table><tr><th>Message:</th><td>OK</td></tr></table>
<table><tr><th>Applications</th></tr>
<tr><td>/ &mdash; Welcome to Tomcat &mdash; running &mdash; 0 sessions</td></tr>
<tr><td>/manager &mdash; Tomcat Manager Application &mdash; running &mdash; 0 sessions</td></tr>
<tr><td>/examples &mdash; Servlet and JSP Examples &mdash; running &mdash; 0 sessions</td></tr></table>
<p>Apache Tomcat/9.0.71</p></body></html>
`},
	"jenkins": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Sign in [Jenkins]</title>
<link rel="stylesheet" href="/static/8a3c1b2f/css/layout.css"></head>
<body class="yui-skin-sam"><div id="main-panel"><h1>Sign in to Jenkins</h1>
<form method="post" name="login" action="j_spring_security_check">
<label for="j_username">Username</label><input name="j_username" id="j_username" type="text" autocomplete="username">
<label for="j_password">Password</label><input name="j_password" id="j_password" type="password" autocomplete="current-password">
<input name="Submit" type="submit" value="Sign in"></form></div>
<footer>Jenkins 2.387.3</footer></body></html>
`},
	"grafana": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Grafana</title>
<base href="/"><link rel="stylesheet" href="public/build/grafana.dark.css"></head>
<body class="theme-dark"><div id="reactRoot"></div>
<script>window.grafanaBootData={user:{isSignedIn:false,orgName:"Main Org."},settings:{appUrl:"/",buildInfo:{version:"9.3.6",edition:"OSS"},loginError:""}};</script>
</body></html>
`},
	"actuator": {"application/vnd.spring-boot.actuator.v3+json", `{"_links":{"self":{"href":"http://localhost:8080/actuator","templated":false},
"health":{"href":"http://localhost:8080/actuator/health","templated":false},
"env":{"href":"http://localhost:8080/actuator/env","templated":false},
"beans":{"href":"http://localhost:8080/actuator/beans","templated":false},
"mappings":{"href":"http://localhost:8080/actuator/mappings","templated":false},
"heapdump":{"href":"http://localhost:8080/actuator/heapdump","templated":false}}}
`},
	"elasticsearch": {"application/json; charset=utf-8", `{
  "name" : "node-1",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "DECOY0000000000000000A",
  "version" : {
    "number" : "7.17.9",
    "build_flavor" : "default",
    "build_type" : "deb",
    "lucene_version" : "8.11.1"
  },
  "tagline" : "You Know, for Search"
}
`},
	"aws-credentials": {"text/plain; charset=utf-8", `[default]
aws_access_key_id = AKIADECOY000000EXAMPLE
aws_secret_access_key = decoy/secret/not/real/0000000000000000
region = eu-north-1

[deploy]
aws_access_key_id = AKIADECOY111111EXAMPLE
aws_secret_access_key = decoy/secret/not/real/1111111111111111
region = eu-west-1
`},
	"ssh-key": {"text/plain; charset=utf-8", `-----BEGIN OPENSSH PRIVATE KEY-----
ZGVjb3kga2V5IC0gbm90IGEga2V5IC0gdGhpcyBpcyBhIGhvbmV5cG90IHJlc3BvbnNlIGFu
ZCBjb250YWlucyBubyBrZXkgbWF0ZXJpYWwgd2hhdHNvZXZlci4gSWYgeW91IGFyZSByZWFk
aW5nIHRoaXMgaW4gYSBzY2FuIHJlcG9ydCwgdGhlIHNjYW4gd2FzIG5vdGljZWQuIDAwMDAw
MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=
-----END OPENSSH PRIVATE KEY-----
`},
	"kubeconfig": {"text/plain; charset=utf-8", `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://kubernetes.internal:6443
    certificate-authority-data: ZGVjb3ktY2EtMDAwMA==
  name: production
contexts:
- context:
    cluster: production
    user: deploy
  name: production
current-context: production
users:
- name: deploy
  user:
    token: decoy.token.not.real.0000000000000000
`},
	"docker-compose": {"text/plain; charset=utf-8", `version: "3.8"
services:
  web:
    image: registry.example.internal/platform/web:1.14.2
    environment:
      DATABASE_URL: postgres://app:decoy-Passw0rd@db:5432/app
      SECRET_KEY_BASE: decoy0000000000000000000000000000000000
    ports: ["8080:8080"]
  db:
    image: postgres:14
    environment:
      POSTGRES_PASSWORD: decoy-Passw0rd
    volumes: ["dbdata:/var/lib/postgresql/data"]
volumes:
  dbdata:
`},
	"wp-config": {"text/plain; charset=utf-8", `<?php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wp' );
define( 'DB_PASSWORD', 'decoy-Passw0rd' );
define( 'DB_HOST', 'localhost' );
define( 'AUTH_KEY',        'decoy 0000000000000000000000000000' );
define( 'SECURE_AUTH_KEY', 'decoy 1111111111111111111111111111' );
$table_prefix = 'wp_';
define( 'WP_DEBUG', false );
require_once ABSPATH . 'wp-settings.php';
`},
	"htpasswd": {"text/plain; charset=utf-8", `admin:$apr1$decoy000$0000000000000000000000
deploy:$apr1$decoy111$1111111111111111111111
monitor:$apr1$decoy222$2222222222222222222222
`},
	"backup-sql": {"application/sql", `-- MySQL dump 10.13  Distrib 8.0.32, for Linux (x86_64)
-- Host: localhost    Database: app
-- ------------------------------------------------------
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
DROP TABLE IF EXISTS ` + "`users`" + `;
CREATE TABLE ` + "`users`" + ` (
  ` + "`id`" + ` int NOT NULL AUTO_INCREMENT,
  ` + "`email`" + ` varchar(255) NOT NULL,
  ` + "`password_hash`" + ` varchar(255) NOT NULL,
  PRIMARY KEY (` + "`id`" + `)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT INTO ` + "`users`" + ` VALUES (1,'decoy@example.invalid','$2y$10$decoy00000000000000000000000000000000000000000000000');
-- Dump completed
`},
	"s3-listing": {"application/xml", `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>example-backups</Name><Prefix></Prefix><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>
  <Contents><Key>db/2026-09-01.sql.gz</Key><LastModified>2026-09-01T02:14:11.000Z</LastModified><Size>418340119</Size><StorageClass>STANDARD</StorageClass></Contents>
  <Contents><Key>db/2026-09-02.sql.gz</Key><LastModified>2026-09-02T02:14:09.000Z</LastModified><Size>418902771</Size><StorageClass>STANDARD</StorageClass></Contents>
</ListBucketResult>
`},
	"swagger": {"application/json; charset=utf-8", `{"openapi":"3.0.3","info":{"title":"Internal Platform API","version":"2.4.1"},
"servers":[{"url":"https://api.example.internal/v2"}],
"paths":{"/users":{"get":{"summary":"List users","responses":{"200":{"description":"ok"}}}},
"/users/{id}/token":{"post":{"summary":"Mint a service token","responses":{"201":{"description":"created"}}}},
"/admin/export":{"get":{"summary":"Export everything","responses":{"200":{"description":"ok"}}}}},
"components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}}}
`},
	"debug-vars": {"application/json; charset=utf-8", `{
"cmdline": ["/usr/local/bin/app","-config","/etc/app/config.yaml"],
"memstats": {"Alloc":18446744,"TotalAlloc":98765432,"Sys":73400320,"NumGC":412},
"requests": 1048576,
"build": "2026-08-14T09:11:02Z"
}
`},
	"server-status": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><title>Apache Status</title></head><body>
<h1>Apache Server Status for web01 (via 10.0.3.14)</h1>
<dl><dt>Server Version: Apache/2.4.52 (Ubuntu)</dt>
<dt>Server MPM: event</dt><dt>Current Time: Monday, 20-Sep-2026 11:14:02 UTC</dt>
<dt>Parent Server Config. Generation: 3</dt>
<dt>1 requests currently being processed, 49 idle workers</dt></dl>
<table><tr><th>Srv</th><th>PID</th><th>Acc</th><th>M</th><th>CPU</th><th>Client</th><th>VHost</th><th>Request</th></tr>
<tr><td>0-0</td><td>2841</td><td>0/12/4011</td><td>_</td><td>0.31</td><td>10.0.3.9</td><td>app.example.internal</td><td>GET /healthz HTTP/1.1</td></tr>
</table></body></html>
`},
	"webshell": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><title>uploader</title></head><body bgcolor="#000000" text="#00ff00">
<pre>
 uname -a : Linux web01 5.4.0-150-generic #167-Ubuntu SMP x86_64
 user     : www-data (33)
 pwd      : /var/www/html
</pre>
<form method="post"><input type="text" name="cmd" size="60" style="background:#000;color:#0f0"><input type="submit" value="run"></form>
<form method="post" enctype="multipart/form-data"><input type="file" name="f"><input type="submit" value="upload"></form>
</body></html>
`},
	"idrac": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Integrated Remote Access Controller</title></head>
<body><div class="login"><h1>Integrated Remote Access Controller 9</h1>
<form method="post" action="/data/login">
<label>Username <input name="user" autocomplete="username"></label>
<label>Password <input type="password" name="password" autocomplete="current-password"></label>
<label>Domain <select name="domain"><option>This iDRAC</option></select></label>
<button type="submit">Log In</button></form>
<p>Firmware 5.10.30.00 &mdash; Service Tag DECOY01</p></div></body></html>
`},
	"webmail": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Webmail :: Welcome to Webmail</title>
<link rel="stylesheet" href="/skins/elastic/styles/styles.min.css"></head>
<body class="task-login"><div id="layout"><form name="form" method="post" action="/?_task=login">
<input type="hidden" name="_token" value="decoy0000000000000000000000000000">
<label for="rcmloginuser">Username</label><input name="_user" id="rcmloginuser" autocomplete="username">
<label for="rcmloginpwd">Password</label><input type="password" name="_pass" id="rcmloginpwd" autocomplete="current-password">
<button type="submit">Login</button></form></div></body></html>
`},

	// ---- Secrets and build files -------------------------------------
	// The files a developer machine leaves behind and a scanner knows by
	// name. Each carries a token shaped like the real thing so a scanner
	// that grades its finds scores it, and none of them is a token.
	"npmrc": {"text/plain; charset=utf-8", `registry=https://registry.example.internal/repository/npm-group/
//registry.example.internal/repository/npm-group/:_authToken=decoy0000-0000-0000-0000-000000000000
//registry.npmjs.org/:_authToken=npm_decoy00000000000000000000000000000000
@platform:registry=https://registry.example.internal/repository/npm-private/
always-auth=true
`},
	"pypirc": {"text/plain; charset=utf-8", `[distutils]
index-servers =
    pypi
    internal

[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmcDECOY0000000000000000000000000000000000

[internal]
repository = https://pypi.example.internal/simple/
username = deploy
password = decoy-Passw0rd
`},
	"gitlab-ci": {"text/plain; charset=utf-8", `stages: [build, test, deploy]

variables:
  REGISTRY: registry.example.internal
  DEPLOY_TOKEN: glpat-decoy0000000000000000
  SSH_KNOWN_HOSTS: deploy.example.internal

build:
  stage: build
  script:
    - docker login -u gitlab-ci-token -p $DEPLOY_TOKEN $REGISTRY
    - docker build -t $REGISTRY/platform/web:$CI_COMMIT_SHA .

deploy:
  stage: deploy
  only: [main]
  script:
    - ssh deploy@app01.example.internal "systemctl restart web"
`},
	"terraform-state": {"application/json", `{
  "version": 4,
  "terraform_version": "1.6.6",
  "serial": 412,
  "lineage": "decoy000-0000-0000-0000-000000000000",
  "outputs": {
    "db_password": {"value": "decoy-Passw0rd", "type": "string", "sensitive": true},
    "api_endpoint": {"value": "https://api.example.internal", "type": "string"}
  },
  "resources": [
    {"mode": "managed", "type": "aws_db_instance", "name": "app",
     "instances": [{"attributes": {"endpoint": "app.decoy.eu-north-1.rds.amazonaws.com:5432", "username": "app"}}]}
  ]
}
`},
	"vscode-sftp": {"application/json", `{
  "name": "production",
  "host": "app01.example.internal",
  "protocol": "sftp",
  "port": 22,
  "username": "deploy",
  "password": "decoy-Passw0rd",
  "remotePath": "/var/www/html",
  "uploadOnSave": true,
  "ignore": [".vscode", ".git", "node_modules"]
}
`},
	"appsettings": {"application/json", `{
  "Logging": {"LogLevel": {"Default": "Information"}},
  "AllowedHosts": "*",
  "ConnectionStrings": {
    "Default": "Server=db01.example.internal;Database=app;User Id=app;Password=decoy-Passw0rd;"
  },
  "Jwt": {"Issuer": "https://api.example.internal", "Key": "decoy00000000000000000000000000000000"},
  "Smtp": {"Host": "smtp.example.internal", "User": "noreply", "Password": "decoy-Passw0rd"}
}
`},
	"database-yml": {"text/plain; charset=utf-8", `default: &default
  adapter: postgresql
  encoding: unicode
  pool: 25

production:
  <<: *default
  host: db01.example.internal
  database: app_production
  username: app
  password: decoy-Passw0rd

staging:
  <<: *default
  host: db02.example.internal
  database: app_staging
  username: app
  password: decoy-Passw0rd
`},
	"nginx-config": {"text/plain; charset=utf-8", `user www-data;
worker_processes auto;

http {
    upstream app { server 10.0.3.11:8080; server 10.0.3.12:8080; }

    server {
        listen 443 ssl;
        server_name app.example.internal;
        ssl_certificate     /etc/ssl/certs/app.pem;
        ssl_certificate_key /etc/ssl/private/app.key;

        location /internal/ {
            allow 10.0.0.0/8;
            deny all;
            proxy_pass http://app;
            proxy_set_header X-Internal-Token decoy0000000000000000;
        }
    }
}
`},

	// ---- Cloud and orchestration APIs --------------------------------
	// A request for one of these on a public proxy is almost always a
	// server side request forgery probe rather than a path scan: the
	// attacker is asking the proxy to fetch its own credentials.
	"imds": {"text/plain; charset=utf-8", `{
  "Code" : "Success",
  "LastUpdated" : "2026-09-20T09:14:11Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIADECOY000000EXAMPLE",
  "SecretAccessKey" : "decoy/secret/not/real/0000000000000000",
  "Token" : "DECOY0000000000000000000000000000000000000000000000000000",
  "Expiration" : "2026-09-20T15:14:11Z"
}
`},
	"consul": {"application/json", `{
  "consul": [],
  "app": ["primary", "eu-north-1a"],
  "db": ["primary"],
  "vault": ["active"],
  "redis": ["cache"]
}
`},
	"vault": {"application/json", `{
  "type": "shamir",
  "initialized": true,
  "sealed": false,
  "t": 3,
  "n": 5,
  "progress": 0,
  "version": "1.15.2",
  "cluster_name": "vault-production",
  "cluster_id": "decoy000-0000-0000-0000-000000000000"
}
`},
	"docker-api": {"application/json", `[
  {"Id":"decoy00000000","Names":["/web"],"Image":"registry.example.internal/platform/web:1.14.2",
   "State":"running","Status":"Up 6 days","Ports":[{"PrivatePort":8080,"PublicPort":8080,"Type":"tcp"}]},
  {"Id":"decoy11111111","Names":["/db"],"Image":"postgres:14","State":"running","Status":"Up 6 days",
   "Mounts":[{"Source":"/var/lib/docker/volumes/dbdata/_data","Destination":"/var/lib/postgresql/data"}]}
]
`},
	"kubelet": {"application/json", `{"kind":"PodList","apiVersion":"v1","items":[
{"metadata":{"name":"web-7d9f4c6b8-2xqkz","namespace":"production"},
 "spec":{"nodeName":"node01","serviceAccountName":"deploy",
  "containers":[{"name":"web","image":"registry.example.internal/platform/web:1.14.2",
   "env":[{"name":"DATABASE_URL","value":"postgres://app:decoy-Passw0rd@db:5432/app"}]}]},
 "status":{"phase":"Running","podIP":"10.244.1.17"}}]}
`},

	// ---- Data stores and dashboards ----------------------------------
	"couchdb": {"application/json", `["_replicator","_users","app","sessions","audit_2026"]
`},
	"solr": {"application/json", `{
  "responseHeader":{"status":0,"QTime":3},
  "initFailures":{},
  "status":{
    "products":{"name":"products","instanceDir":"/var/solr/data/products","dataDir":"/var/solr/data/products/data/",
      "index":{"numDocs":1841203,"segmentCount":14,"sizeInBytes":4183401190}},
    "customers":{"name":"customers","instanceDir":"/var/solr/data/customers",
      "index":{"numDocs":412884,"segmentCount":9,"sizeInBytes":918902771}}}
}
`},
	"rabbitmq": {"application/json", `{
  "management_version": "3.11.13",
  "rabbitmq_version": "3.11.13",
  "cluster_name": "rabbit@mq01.example.internal",
  "erlang_version": "25.3",
  "queue_totals": {"messages": 1841, "messages_ready": 1802, "messages_unacknowledged": 39},
  "object_totals": {"connections": 42, "channels": 84, "exchanges": 11, "queues": 27, "consumers": 36},
  "listeners": [{"node":"rabbit@mq01","protocol":"amqp","port":5672},
                {"node":"rabbit@mq01","protocol":"http","port":15672}]
}
`},
	"kibana": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Elastic</title>
<link rel="stylesheet" href="/ui/legacy_styles.css"></head>
<body><div class="kibanaWelcomeView" id="kbn_loading_message"><div class="kibanaWelcomeLogoCircle">
<div class="kibanaWelcomeLogo"></div></div><div class="kibanaWelcomeText">Loading Elastic</div></div>
<script>window.__kbnStrictCsp__=false;window.__kbnPublicPath__={"kbn-ui-shared-deps":"/bundles/kbn-ui-shared-deps/"};
window.__kbnBootstrapConfig__={"version":"8.7.1","buildNumber":61230,"basePath":"","serverName":"kibana-prod"};</script>
</body></html>
`},
	"prometheus-config": {"application/json", `{"status":"success","data":{"yaml":"global:\n  scrape_interval: 15s\nscrape_configs:\n- job_name: app\n  static_configs:\n  - targets: [app01.example.internal:9090, app02.example.internal:9090]\n  authorization:\n    credentials: decoy0000000000000000\n- job_name: node\n  static_configs:\n  - targets: [node01.example.internal:9100]\n"}}
`},
	"traefik": {"application/json", `{
  "routers": {
    "app@docker": {"entryPoints":["websecure"],"service":"app","rule":"Host(\"app.example.internal\")","status":"enabled"},
    "api@file": {"entryPoints":["websecure"],"service":"api","rule":"PathPrefix(\"/v2\")","status":"enabled","middlewares":["auth@file"]}
  },
  "middlewares": {
    "auth@file": {"basicAuth":{"users":["admin:$apr1$decoy000$0000000000000000000000"]},"status":"enabled"}
  },
  "services": {
    "app@docker": {"loadBalancer":{"servers":[{"url":"http://10.0.3.11:8080"},{"url":"http://10.0.3.12:8080"}]},"status":"enabled"}
  }
}
`},

	// ---- Enterprise front doors --------------------------------------
	// The login pages a mass scanner fingerprints before it picks an
	// exploit. Answering one costs the scanner a round trip and tells
	// this proxy exactly what the client came for.
	"confluence": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Log In - Confluence</title>
<link rel="stylesheet" href="/s/decoy/_/styles/combined.css"></head>
<body id="com-atlassian-confluence" class="theme-default aui-layout"><div id="full-height-container">
<form name="loginform" method="post" action="/dologin.action" class="aui">
<h2>Log in to Confluence</h2>
<label for="os_username">Username</label><input type="text" id="os_username" name="os_username" autocomplete="username">
<label for="os_password">Password</label><input type="password" id="os_password" name="os_password" autocomplete="current-password">
<input type="hidden" name="login" value="Log in"><button type="submit" class="aui-button aui-button-primary">Log in</button>
</form><footer>Atlassian Confluence 7.13.7</footer></div></body></html>
`},
	"gitlab-login": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en" class="gl-h-full"><head><meta charset="utf-8"><title>Sign in &middot; GitLab</title>
<link rel="stylesheet" href="/assets/application-decoy.css"></head>
<body class="login-page"><div class="container"><h1 class="gl-sr-only">GitLab</h1>
<form class="gl-show-field-errors" action="/users/sign_in" method="post">
<input type="hidden" name="authenticity_token" value="decoy0000000000000000000000000000000000000000">
<label for="user_login">Username or email</label><input id="user_login" name="user[login]" autocomplete="username">
<label for="user_password">Password</label><input id="user_password" type="password" name="user[password]" autocomplete="current-password">
<button type="submit" class="btn btn-confirm">Sign in</button></form>
<p class="gl-text-center">GitLab Community Edition 15.9.3</p></div></body></html>
`},
	"citrix": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Citrix Gateway</title>
<link rel="stylesheet" href="/vpn/css/base.css"></head>
<body class="login-body"><div id="logonbelt-container"><div id="logonbelt-topshadow"></div>
<form id="logonForm" method="post" action="/cgi/login" name="vpnForm">
<h2>Please log on</h2>
<label for="login">User name</label><input id="login" name="login" type="text" autocomplete="username">
<label for="passwd">Password</label><input id="passwd" name="passwd" type="password" autocomplete="current-password">
<input type="hidden" name="dummy_username"><input type="hidden" name="dummy_pass">
<button type="submit" id="Log_On">Log On</button></form>
<div id="footer">NetScaler Gateway 13.0-87.9</div></div></body></html>
`},
	"fortinet": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Please Login</title>
<link rel="stylesheet" href="/sslvpn/css/login.css"></head>
<body onload="document.getElementById('username').focus()"><div class="sslvpn-login">
<div class="brand">FortiGate SSL-VPN</div>
<form method="post" action="/remote/logincheck">
<label for="username">Name</label><input id="username" name="username" type="text" autocomplete="username">
<label for="credential">Password</label><input id="credential" name="credential" type="password" autocomplete="current-password">
<input type="hidden" name="realm" value=""><input type="hidden" name="ajax" value="1">
<button type="submit">Login</button></form>
<div class="version">FortiOS 7.0.12 build0523</div></div></body></html>
`},
	"esxi": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>VMware ESXi</title>
<link rel="stylesheet" href="/ui/scripts/main-decoy.css"></head>
<body><div id="loginContainer"><h1>VMware ESXi</h1>
<form id="loginForm" method="post" action="/ui/login">
<label for="username">User name</label><input id="username" name="username" autocomplete="username">
<label for="password">Password</label><input id="password" type="password" name="password" autocomplete="current-password">
<button type="submit">Log in</button></form>
<p class="build">VMware ESXi 7.0 Update 3 (Build 20328353) &mdash; esx01.example.internal</p></div></body></html>
`},
	"exchange-autodiscover": {"application/xml", `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <User><DisplayName>Decoy User</DisplayName><LegacyDN>/o=example/ou=Exchange/cn=Recipients/cn=decoy</LegacyDN></User>
    <Account><AccountType>email</AccountType><Action>settings</Action>
      <Protocol><Type>EXCH</Type><Server>mbx01.example.internal</Server><ServerVersion>73C0834F</ServerVersion>
        <AuthPackage>Ntlm</AuthPackage><ServerDN>/o=example/ou=Exchange/cn=Configuration/cn=Servers/cn=mbx01</ServerDN></Protocol>
      <Protocol><Type>EXPR</Type><Server>mail.example.internal</Server><SSL>On</SSL><AuthPackage>Basic</AuthPackage></Protocol>
    </Account>
  </Response>
</Autodiscover>
`},

	// ---- Application internals ---------------------------------------
	"wp-users": {"application/json; charset=utf-8", `[
{"id":1,"name":"admin","url":"","description":"","link":"https://example.invalid/author/admin/","slug":"admin"},
{"id":2,"name":"editor","url":"","description":"","link":"https://example.invalid/author/editor/","slug":"editor"},
{"id":7,"name":"deploy","url":"","description":"Service account","link":"https://example.invalid/author/deploy/","slug":"deploy"}
]
`},
	"graphql": {"application/json; charset=utf-8", `{"data":{"__schema":{
"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},
"types":[
{"kind":"OBJECT","name":"Query","fields":[
  {"name":"users","description":"List every user","args":[]},
  {"name":"internalAuditLog","description":"Read the audit log","args":[{"name":"since","type":{"name":"String"}}]}]},
{"kind":"OBJECT","name":"Mutation","fields":[
  {"name":"mintServiceToken","description":"Issue a service token","args":[{"name":"scope","type":{"name":"String"}}]},
  {"name":"impersonate","description":"Act as another user","args":[{"name":"userId","type":{"name":"ID"}}]}]},
{"kind":"OBJECT","name":"User","fields":[
  {"name":"id","args":[]},{"name":"email","args":[]},{"name":"passwordHash","args":[]}]}]}}}
`},
	"laravel-log": {"text/plain; charset=utf-8", `[2026-09-19 02:14:11] production.ERROR: SQLSTATE[08006] connection to server at "db01.example.internal" (10.0.4.11), port 5432 failed {"exception":"[object] (Illuminate\\Database\\QueryException(code: 7): SQLSTATE[08006] at /var/www/html/vendor/laravel/framework/src/Illuminate/Database/Connection.php:760)
[stacktrace]
#0 /var/www/html/vendor/laravel/framework/src/Illuminate/Database/Connection.php(720): Illuminate\\Database\\Connection->runQueryCallback()
#1 /var/www/html/app/Http/Controllers/BillingController.php(88): Illuminate\\Database\\Connection->select()
#2 {main}
"}
[2026-09-19 02:14:12] production.WARNING: Retrying with DB_PASSWORD from env (decoy-Passw0rd)
[2026-09-19 06:03:44] production.INFO: Scheduled export wrote /var/www/html/storage/app/exports/customers-2026-09-19.csv
`},
	"adminer": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Login - Adminer</title>
<link rel="stylesheet" href="adminer.css"></head>
<body class="nojs"><div id="content"><h1><a href="https://www.adminer.org/" id="h1">Adminer</a>
<span class="version">4.8.1</span></h1>
<form action="" method="post"><table cellspacing="0" class="layout">
<tr><th>System<td><select name="auth[driver]"><option value="server">MySQL</option><option value="pgsql">PostgreSQL</option></select>
<tr><th>Server<td><input name="auth[server]" value="db01.example.internal">
<tr><th>Username<td><input name="auth[username]" autocomplete="username">
<tr><th>Password<td><input type="password" name="auth[password]" autocomplete="current-password">
<tr><th>Database<td><input name="auth[db]" value="app">
</table><p><input type="submit" value="Login"></form></div></body></html>
`},
	"cgi-bin": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Router</title></head>
<body><h2>System Management</h2>
<table border="1"><tr><td>Model</td><td>Decoy 2860n</td></tr>
<tr><td>Firmware</td><td>3.9.6.2</td></tr>
<tr><td>WAN IP</td><td>198.51.100.4</td></tr>
<tr><td>LAN IP</td><td>192.168.1.1</td></tr>
<tr><td>Uptime</td><td>141 days 06:22:18</td></tr></table>
<form method="post" action="/cgi-bin/mainfunction.cgi">
<label>User <input name="username" autocomplete="username"></label>
<label>Password <input type="password" name="password" autocomplete="current-password"></label>
<input type="submit" value="Login"></form></body></html>
`},
	// Cloud metadata services other than AWS. A request for one of
	// these on a public proxy is a server side request forgery probe:
	// the client is asking the proxy to fetch its own credentials.
	"gcp-metadata": {"application/json", `{"access_token":"ya29.decoy-not-a-real-token-0000000000000000000000",
"expires_in":3599,
"token_type":"Bearer",
"email":"decoy-runtime@example-project.iam.gserviceaccount.example",
"scopes":["https://www.googleapis.example/auth/cloud-platform"]}
`},
	"azure-imds": {"application/json", `{"compute":{"azEnvironment":"AzurePublicCloud","location":"westeurope",
"name":"decoy-vm-01","osType":"Linux","resourceGroupName":"rg-decoy","subscriptionId":"00000000-0000-0000-0000-000000000000",
"vmId":"00000000-0000-0000-0000-000000000000","vmSize":"Standard_D2s_v3","tags":"env:example"},
"network":{"interface":[{"ipv4":{"ipAddress":[{"privateIpAddress":"10.0.0.4","publicIpAddress":"198.51.100.4"}],
"subnet":[{"address":"10.0.0.0","prefix":"24"}]},"macAddress":"000000000000"}]}}
`},

	// Registries, pipelines and platform consoles.
	"registry-catalog": {"application/json", `{"repositories":["example/api","example/web","example/worker","example/db-backup","example/ci-runner"]}
`},
	"argocd": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Argo CD</title>
<link rel="stylesheet" href="/assets/app.css"></head>
<body><div id="app"><div class="login"><h2>Argo CD</h2>
<form method="post" action="/api/v1/session">
<label>Username <input name="username" autocomplete="username"></label>
<label>Password <input type="password" name="password" autocomplete="current-password"></label>
<button type="submit">Sign In</button></form>
<p class="version">argocd v2.6.7+unknown</p></div></div></body></html>
`},
	"keycloak": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Sign in to master</title>
<link rel="stylesheet" href="/resources/login/keycloak/css/login.css"></head>
<body class="login-pf"><div id="kc-form"><h1 id="kc-page-title">Sign in to your account</h1>
<form id="kc-form-login" action="/realms/master/login-actions/authenticate" method="post">
<label for="username">Username or email</label><input id="username" name="username" type="text" autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
<input type="hidden" name="credentialId"><input type="submit" value="Sign In"></form>
<div id="kc-info"><p>Keycloak 21.0.1</p></div></div></body></html>
`},

	// Application servers whose consoles have their own exploit history.
	"weblogic": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><title>Oracle WebLogic Server Administration Console</title>
<link rel="stylesheet" href="/console/framework/skins/wlsconsole/css/console.css"></head>
<body><div id="wrap"><h1>Welcome</h1>
<p>Log in to work with the WebLogic Server domain</p>
<form method="post" action="/console/j_security_check" name="loginData">
<label>Username <input name="j_username" type="text" autocomplete="username"></label>
<label>Password <input name="j_password" type="password" autocomplete="current-password"></label>
<input type="submit" value="Login"></form>
<p class="footer">WebLogic Server Version: 12.2.1.4.0</p></div></body></html>
`},
	"jboss": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Management Interface</title>
<link rel="stylesheet" href="/console/css/console.css"></head>
<body><div class="header"><h1>WildFly Management Console</h1></div>
<div class="content"><table><tr><th>Deployment</th><th>Status</th></tr>
<tr><td>api.war</td><td>OK</td></tr><tr><td>reporting.war</td><td>OK</td></tr>
<tr><td>jmx-console.war</td><td>OK</td></tr></table>
<p>WildFly Full 26.1.3.Final (WildFly Core 18.1.2.Final)</p></div></body></html>
`},
	"coldfusion": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><title>ColdFusion Administrator Login</title>
<link rel="stylesheet" href="/CFIDE/administrator/templates/admin.css"></head>
<body><div id="loginbox"><h1>ColdFusion Administrator</h1>
<form name="loginform" action="/CFIDE/administrator/index.cfm" method="post">
<label>User Name <input type="text" name="cfadminUserId" autocomplete="username"></label>
<label>Password <input type="password" name="cfadminPassword" autocomplete="current-password"></label>
<input type="submit" name="submit" value="Login"></form>
<p>ColdFusion 2018 Release, Update 15</p></div></body></html>
`},
	"aspnet-trace": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><title>Application Trace</title></head>
<body bgcolor="white"><span style="font-family:Verdana;font-size:14pt"><b>Application Trace</b></span>
<table cellpadding="0" cellspacing="0"><tr><th>No.</th><th>Time of Request</th><th>File</th><th>Status Code</th><th>Verb</th></tr>
<tr><td>1</td><td>03/11/2026 09:14:02</td><td>/Default.aspx</td><td>200</td><td>GET</td></tr>
<tr><td>2</td><td>03/11/2026 09:14:06</td><td>/Account/Login.aspx</td><td>200</td><td>POST</td></tr>
<tr><td>3</td><td>03/11/2026 09:15:44</td><td>/Reports/Export.aspx</td><td>302</td><td>GET</td></tr></table>
<p>Physical Directory: d:\inetpub\wwwroot\example\</p></body></html>
`},

	// Configuration and interface documents that are XML on the wire.
	"web-config": {"text/xml; charset=utf-8", `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="DefaultConnection" connectionString="Server=db01.example.invalid;Database=app;User Id=app;Password=decoy-Passw0rd-not-real;" providerName="System.Data.SqlClient" />
  </connectionStrings>
  <appSettings>
    <add key="Environment" value="Production" />
    <add key="ApiKey" value="decoy-api-key-0000000000000000" />
  </appSettings>
  <system.web>
    <compilation debug="false" targetFramework="4.7.2" />
    <customErrors mode="Off" />
  </system.web>
</configuration>
`},
	"xmlrpc": {"text/xml; charset=utf-8", `<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><params><param><value><array><data>
<value><string>system.multicall</string></value>
<value><string>system.listMethods</string></value>
<value><string>wp.getUsersBlogs</string></value>
<value><string>wp.getPosts</string></value>
<value><string>pingback.ping</string></value>
</data></array></value></param></params></methodResponse>
`},
	"sitemap": {"application/xml", `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://www.example.com/admin/</loc><changefreq>daily</changefreq></url>
<url><loc>https://www.example.com/backup/</loc><changefreq>weekly</changefreq></url>
<url><loc>https://www.example.com/.git/config</loc><changefreq>monthly</changefreq></url>
<url><loc>https://www.example.com/wp-login.php</loc><changefreq>daily</changefreq></url>
<url><loc>https://www.example.com/phpmyadmin/</loc><changefreq>weekly</changefreq></url>
</urlset>
`},
	"minio": {"application/xml", `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Access Denied.</Message>
<BucketName>example-backups</BucketName><Key></Key>
<Resource>/example-backups</Resource>
<RequestId>17A1B2C3D4E5F600</RequestId>
<HostId>decoy-host-id-not-real</HostId></Error>
`},
	"camera": {"application/xml", `<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="2.0" xmlns="http://www.example.com/ver20/XMLSchema">
<deviceName>Camera-Lobby-01</deviceName>
<deviceID>decoy-0000-0000</deviceID>
<model>DS-EXAMPLE-I8</model>
<serialNumber>DS-EXAMPLE0000000000DECOY</serialNumber>
<firmwareVersion>V5.5.82</firmwareVersion>
<macAddress>00:00:00:00:00:00</macAddress>
<ipAddress>192.168.1.64</ipAddress>
</DeviceInfo>
`},

	// Notebooks, models and query front ends: the newer end of what a
	// scanner looks for.
	"jupyter": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Jupyter Notebook</title>
<link rel="stylesheet" href="/static/style/style.min.css"></head>
<body class="login"><div id="ipython-main-app" class="container">
<h1>Token authentication is enabled</h1>
<p class="hint">Example deployment; the token is in the server log.</p>
<form action="/login?next=%2Ftree" method="post" class="form-inline">
<label for="password_input">Password or token:</label>
<input type="password" name="password" id="password_input" class="form-control">
<button type="submit" class="btn btn-default">Log in</button></form>
<p>Notebook Server 6.5.4</p></div></body></html>
`},
	"ollama": {"application/json", `{"models":[
{"name":"llama3:8b","model":"llama3:8b","size":4661224676,"digest":"decoy0000000000000000000000000000000000000000000000000000000000","details":{"family":"llama","parameter_size":"8B","quantization_level":"Q4_0"}},
{"name":"internal-support-assistant:latest","model":"internal-support-assistant:latest","size":3825819519,"digest":"decoy1111111111111111111111111111111111111111111111111111111111","details":{"family":"llama","parameter_size":"7B","quantization_level":"Q4_K_M"}}]}
`},
	"clickhouse": {"text/plain; charset=utf-8", `analytics
billing_archive
default
events
information_schema
staging_example
system
`},

	// Remote access appliances. These are fingerprinted in bulk before
	// an exploit is chosen, so answering tells the proxy what the
	// scanner came shopping for.
	"ivanti": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Welcome</title>
<link rel="stylesheet" href="/dana-na/css/ds.css"></head>
<body class="dsSigninPage"><div id="dslogin"><h1>Welcome to the Secure Access Gateway</h1>
<form name="frmLogin" action="/dana-na/auth/url_default/login.cgi" method="post">
<label>Username <input name="username" type="text" autocomplete="username"></label>
<label>Password <input name="password" type="password" autocomplete="current-password"></label>
<input type="hidden" name="realm" value="Users">
<input type="submit" value="Sign In"></form>
<p class="footer">Secure Access 22.3R1</p></div></body></html>
`},
	"nextcloud": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Login &ndash; Nextcloud</title>
<link rel="stylesheet" href="/core/css/server.css"></head>
<body id="body-login"><div class="wrapper"><header><h1>Nextcloud</h1></header>
<form method="post" name="login" action="/login">
<label for="user">Account name or email</label><input type="text" name="user" id="user" autocomplete="username">
<label for="password">Password</label><input type="password" name="password" id="password" autocomplete="current-password">
<input type="hidden" name="requesttoken" value="decoy-token-not-real">
<button type="submit">Log in</button></form>
<p class="version">Nextcloud 25.0.4</p></div></body></html>
`},
	"cpanel": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>cPanel Login</title>
<link rel="stylesheet" href="/unprotected/cpanel.css"></head>
<body class="lang-en"><div id="login_container"><h1>cPanel</h1>
<form id="login_form" action="/login/?login_only=1" method="post">
<label for="user">Username</label><input id="user" name="user" type="text" autocomplete="username">
<label for="pass">Password</label><input id="pass" name="pass" type="password" autocomplete="current-password">
<button type="submit">Log in</button></form>
<div id="footer">cPanel &amp; WHM 110.0.11</div></div></body></html>
`},
	"printer": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Printer Status</title></head>
<body><h1>Office Printer 2F-East</h1>
<table border="1"><tr><td>Model</td><td>Example LaserJet M404dn</td></tr>
<tr><td>Serial</td><td>DECOY0000000</td></tr>
<tr><td>Status</td><td>Ready</td></tr>
<tr><td>Black Toner</td><td>62%</td></tr>
<tr><td>Pages Printed</td><td>148,302</td></tr>
<tr><td>Address</td><td>192.168.4.31</td></tr></table>
<p><a href="/hp/device/set_config_deviceInfo.html">Device configuration</a></p></body></html>
`},

	// Source control, build and artefact servers. A scanner that finds
	// one of these is after the credentials inside it, not the service.
	"gitea": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Sign In - Gitea: Git with a cup of tea</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body><div class="page-content"><h1>Sign In</h1>
<form action="/user/login" method="post">
<input type="hidden" name="_csrf" value="decoy-csrf-not-real">
<label>Username or Email Address<input name="user_name" autocomplete="username"></label>
<label>Password<input name="password" type="password" autocomplete="current-password"></label>
<label><input type="checkbox" name="remember"> Remember this device</label>
<button type="submit">Sign In</button></form>
<p class="version">Powered by Gitea Version: 1.19.3</p></div></body></html>
`},
	"teamcity": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Log in to TeamCity</title>
<link rel="stylesheet" href="/css/login.css"></head>
<body><div id="loginPage"><h1>TeamCity</h1>
<form id="loginForm" action="/loginSubmit.html" method="post">
<label for="username">Username</label><input id="username" name="username" autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
<input type="submit" value="Log in"></form>
<div class="version">TeamCity Professional 2022.10.3 (build 116751)</div></div></body></html>
`},
	"nexus": {"application/json", `{"items":[
{"id":"decoy0","repository":"maven-releases","name":"com/example/internal-billing","version":"4.2.1","format":"maven2"},
{"id":"decoy1","repository":"npm-internal","name":"@example/deploy-scripts","version":"0.9.7","format":"npm"},
{"id":"decoy2","repository":"docker-private","name":"example/payments-api","version":"2024.3","format":"docker"}],
"continuationToken":null}
`},
	"svn-entries": {"text/plain; charset=utf-8", `12
dir
41284
https://svn.example.internal/repos/site/trunk
https://svn.example.internal/repos/site
2019-11-04T09:12:44.000000Z
41201
build-agent
config
dir
db
dir
deploy.sh
file
`},
	"idea-workspace": {"application/xml", `<?xml version="1.0" encoding="UTF-8"?>
<project version="4">
  <component name="ChangeListManager">
    <list default="true" id="decoy-0000" name="Default Changelist" comment="" />
  </component>
  <component name="RunManager">
    <configuration name="deploy-staging" type="ShConfigurationType">
      <option name="SCRIPT_TEXT" value="./deploy.sh staging" />
      <option name="SCRIPT_PATH" value="$PROJECT_DIR$/deploy.sh" />
    </configuration>
  </component>
  <component name="PropertiesComponent">
    <property name="last.opened.file.path" value="$PROJECT_DIR$/config/settings.example.yml" />
  </component>
</project>
`},

	// Container and cluster management. These get scanned in bulk by
	// crypto-mining crawlers, which is why they answer plausibly and
	// then say nothing more.
	"portainer": {"application/json", `{"Version":"2.18.3","InstanceID":"decoy-0000-0000-0000","DemoEnvironment":{"Enabled":false},"Edition":"CE"}
`},
	"rancher": {"application/json", `{"type":"collection","resourceType":"cluster","data":[
{"id":"c-decoy0","type":"cluster","name":"production","state":"active","provider":"rke","k8sVersion":"v1.26.4"},
{"id":"c-decoy1","type":"cluster","name":"staging","state":"active","provider":"rke","k8sVersion":"v1.25.9"}]}
`},
	"etcd": {"application/json", `{"action":"get","node":{"dir":true,"nodes":[
{"key":"/registry","dir":true,"modifiedIndex":18,"createdIndex":18},
{"key":"/deployment","dir":true,"modifiedIndex":204,"createdIndex":204},
{"key":"/service-config","dir":true,"modifiedIndex":871,"createdIndex":871}]}}
`},
	"nomad": {"application/json", `[{"ID":"batch-reindex","Name":"batch-reindex","Type":"batch","Status":"dead","Datacenters":["dc1"],"JobSummary":{"JobID":"batch-reindex"}},
{"ID":"api","Name":"api","Type":"service","Status":"running","Datacenters":["dc1"],"JobSummary":{"JobID":"api"}}]
`},
	"spark": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Spark Master at spark://master:7077</title>
<link rel="stylesheet" href="/static/bootstrap.min.css"></head>
<body><div class="container-fluid"><h3>Spark Master at spark://master:7077</h3>
<ul class="list-unstyled">
<li><strong>URL:</strong> spark://master:7077</li>
<li><strong>Alive Workers:</strong> 3</li>
<li><strong>Cores in use:</strong> 24 Total, 0 Used</li>
<li><strong>Memory in use:</strong> 96.0 GiB Total, 0.0 B Used</li>
<li><strong>Status:</strong> ALIVE</li></ul>
<h4>Running Applications</h4><p>No running applications.</p>
<p>Spark 3.3.2</p></div></body></html>
`},
	"hadoop-yarn": {"application/json", `{"clusterInfo":{"id":1700000000000,"startedOn":1700000000000,"state":"STARTED","haState":"ACTIVE",
"resourceManagerVersion":"3.3.4","hadoopVersion":"3.3.4","resourceManagerBuildVersion":"3.3.4 from decoy by example"}}
`},
	"airflow": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Sign In - Airflow</title>
<link rel="stylesheet" href="/static/appbuilder/css/flask-appbuilder.css"></head>
<body class="login"><div class="panel"><h3>Sign In</h3>
<form action="/login/" method="post">
<input type="hidden" name="csrf_token" value="decoy-token-not-real">
<label for="username">Username</label><input id="username" name="username" autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
<button type="submit">Sign In</button></form>
<footer>Apache Airflow 2.5.3</footer></div></body></html>
`},

	// Database consoles and analytics front ends.
	"pgadmin": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>pgAdmin 4</title>
<link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"></head>
<body><div class="login-container"><h4>Login to pgAdmin 4</h4>
<form method="post" action="/login?next=/browser/">
<input type="hidden" name="csrf_token" value="decoy-token-not-real">
<label for="email">Email Address / Username</label><input id="email" name="email" autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
<button type="submit">Login</button></form>
<div class="version">pgAdmin 4 v6.21</div></div></body></html>
`},
	"mongo-express": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Home - Mongo Express</title>
<link rel="stylesheet" href="/public/css/bootstrap.min.css"></head>
<body><div class="container"><h1>Mongo Express</h1>
<h3>Databases</h3><table class="table"><thead><tr><th>Database Name</th><th>Collections</th></tr></thead>
<tbody><tr><td><a href="/db/admin/">admin</a></td><td>3</td></tr>
<tr><td><a href="/db/sessions/">sessions</a></td><td>2</td></tr>
<tr><td><a href="/db/example_app/">example_app</a></td><td>17</td></tr></tbody></table>
<footer>mongo-express 1.0.0-alpha.4</footer></div></body></html>
`},
	"metabase": {"application/json", `{"version":{"tag":"v0.45.2","date":"2023-03-28","branch":"release-x.45.x"},
"setup-token":null,"has-user-setup":true,"engines":{"postgres":{"driver-name":"PostgreSQL"},"mysql":{"driver-name":"MySQL"}},
"site-name":"Example Analytics","anon-tracking-enabled":false}
`},
	"superset": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Sign In - Superset</title>
<link rel="stylesheet" href="/static/appbuilder/css/flask-appbuilder.css"></head>
<body><div class="panel"><h4>Sign In</h4>
<form action="/login/" method="post">
<input type="hidden" name="csrf_token" value="decoy-token-not-real">
<label for="username">Username</label><input id="username" name="username" autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
<button type="submit">Sign In</button></form>
<footer>Apache Superset 2.0.1</footer></div></body></html>
`},
	"zabbix": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Zabbix</title>
<link rel="stylesheet" href="/assets/styles/blue-theme.css"></head>
<body><main><div class="signin-container"><h1>Zabbix</h1>
<form action="index.php" method="post">
<label for="name">Username</label><input id="name" name="name" autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
<button type="submit" name="enter" value="Sign in">Sign in</button></form>
<footer>Zabbix 6.0.17</footer></div></main></body></html>
`},

	// Content management systems, which are probed by version before
	// anything is attempted against them.
	"joomla": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Administration - Log in</title>
<link rel="stylesheet" href="/administrator/templates/atum/css/template.min.css"></head>
<body class="admin com_login"><div class="view-login"><h1>Log in</h1>
<form action="/administrator/index.php" method="post" id="form-login">
<label for="mod-login-username">Username</label><input id="mod-login-username" name="username" autocomplete="username">
<label for="mod-login-password">Password</label><input id="mod-login-password" name="passwd" type="password" autocomplete="current-password">
<input type="hidden" name="option" value="com_login"><input type="hidden" name="task" value="login">
<button type="submit">Log in</button></form>
<div class="footer">Joomla! 4.2.8</div></div></body></html>
`},
	"drupal": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Log in | Example</title>
<meta name="Generator" content="Drupal 9 (https://www.drupal.org)">
<link rel="stylesheet" href="/core/themes/claro/css/base/base.css"></head>
<body class="path-user"><div class="layout-container"><h1>Log in</h1>
<form action="/user/login" method="post" id="user-login-form">
<label for="edit-name">Username</label><input id="edit-name" name="name" autocomplete="username">
<label for="edit-pass">Password</label><input id="edit-pass" name="pass" type="password" autocomplete="current-password">
<input type="hidden" name="form_id" value="user_login_form">
<input type="submit" value="Log in"></form>
<p><a href="/user/password">Reset your password</a></p></div></body></html>
`},
	"magento": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Magento Admin</title>
<link rel="stylesheet" href="/static/adminhtml/Magento/backend/en_US/css/styles.css"></head>
<body class="page-layout-admin-login"><div class="login-content"><h1>Welcome, please sign in</h1>
<form method="post" action="/admin/admin/index/index/">
<input type="hidden" name="form_key" value="decoykeynotreal00">
<label for="username">Username</label><input id="username" name="login[username]" autocomplete="username">
<label for="login">Password</label><input id="login" name="login[password]" type="password" autocomplete="current-password">
<button type="submit">Sign in</button></form>
<p class="copyright">Magento ver. 2.4.5-p1</p></div></body></html>
`},
	"moodle": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Example Learning: Log in</title>
<link rel="stylesheet" href="/theme/styles.php/boost/all"></head>
<body id="page-login-index"><div class="loginform"><h1>Log in to Example Learning</h1>
<form action="/login/index.php" method="post" id="login">
<input type="hidden" name="logintoken" value="decoytokennotreal">
<label for="username">Username</label><input id="username" name="username" autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
<button type="submit">Log in</button></form>
<div class="footer">Moodle 4.1.2+</div></div></body></html>
`},
	"zimbra": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Zimbra Web Client Sign In</title>
<link rel="stylesheet" href="/zimbra/css/login.css"></head>
<body onload="zLoginFocus()"><div class="ZLoginPanel"><h1>Zimbra</h1>
<form method="post" name="loginForm" action="/zimbra/">
<input type="hidden" name="loginOp" value="login">
<label for="username">Username</label><input id="username" name="username" autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
<input type="submit" value="Sign In"></form>
<div class="ZLoginFooterText">Zimbra Collaboration Suite 8.8.15</div></div></body></html>
`},

	// Firewalls and remote access gateways.
	"pfsense": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>gateway.example.internal - Login</title>
<link rel="stylesheet" href="/css/pfSense.css"></head>
<body class="no-menu"><div class="login-form"><h2>Login to gateway.example.internal</h2>
<form method="post" action="/index.php">
<label for="usernamefld">Username</label><input id="usernamefld" name="usernamefld" autocomplete="username">
<label for="passwordfld">Password</label><input id="passwordfld" name="passwordfld" type="password" autocomplete="current-password">
<button type="submit" name="login">Sign In</button></form></div></body></html>
`},
	"sonicwall": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>SonicWall - Authentication</title>
<link rel="stylesheet" href="/styleBlueTheme.css"></head>
<body><div id="authArea"><h2>Secure Remote Access</h2>
<form name="loginForm" method="post" action="/cgi-bin/userLogin">
<label>Username <input name="username" autocomplete="username"></label>
<label>Password <input name="pass" type="password" autocomplete="current-password"></label>
<label>Domain <select name="domain"><option value="LocalDomain">LocalDomain</option></select></label>
<input type="submit" value="Login"></form>
<div class="footer">SMA 10.2.1.2</div></div></body></html>
`},
	"paloalto": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>GlobalProtect Portal</title>
<link rel="stylesheet" href="/global-protect/portal/css/login.css"></head>
<body><div id="container"><h1>GlobalProtect Portal</h1>
<form id="loginForm" method="post" action="/global-protect/login.esp">
<input type="hidden" name="prot" value="https:"><input type="hidden" name="server" value="vpn.example.com">
<label>Name <input name="user" autocomplete="username"></label>
<label>Password <input name="passwd" type="password" autocomplete="current-password"></label>
<input type="submit" value="Log In"></form></div></body></html>
`},
	"cisco-asa": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>SSL VPN Service</title>
<link rel="stylesheet" href="/+CSCOU+/csco_logo.css"></head>
<body><div id="logonbox"><h1>Login</h1>
<p>Please enter your username and password.</p>
<form name="Login" method="post" action="/+webvpn+/index.html">
<label>USERNAME <input name="username" autocomplete="username"></label>
<label>PASSWORD <input name="password" type="password" autocomplete="current-password"></label>
<input type="hidden" name="tgroup" value="DefaultWEBVPNGroup">
<input type="submit" value="Logon"></form></div></body></html>
`},
	"mikrotik": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>router - RouterOS</title>
<link rel="stylesheet" href="/webfig/webfig.css"></head>
<body><div id="login"><h1>RouterOS router</h1>
<form name="login" action="/jsproxy" method="post">
<label>Login <input name="name" autocomplete="username"></label>
<label>Password <input name="password" type="password" autocomplete="current-password"></label>
<input type="submit" value="Login"></form>
<div class="foot">RouterOS v6.49.7 | webfig</div></div></body></html>
`},

	// Framework debug consoles and the probes that hunt them. An answer
	// here is the clearest signal in the set: nothing but a scanner
	// asks for a debugger.
	"werkzeug-console": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Console // Werkzeug Debugger</title>
<link rel="stylesheet" href="?__debugger__=yes&cmd=resource&f=style.css"></head>
<body><div class="debugger"><h1>Interactive Console</h1>
<p>In this console you can execute Python expressions in the context of the application.</p>
<div class="console"><div class="inner">The console is locked and needs to be unlocked by entering the PIN.
You can find the PIN printed out on the standard output of your shell that runs the server.</div></div>
<form><label>PIN <input type="text" name="pin"></label><input type="submit" value="Confirm Pin"></form>
</div></body></html>
`},
	"symfony-profiler": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Symfony Profiler</title>
<link rel="stylesheet" href="/_wdt/css/profiler.css"></head>
<body><div id="summary"><h2>Latest requests</h2>
<table><thead><tr><th>Token</th><th>Method</th><th>URL</th><th>Time</th><th>Status</th></tr></thead>
<tbody><tr><td><a href="/_profiler/decoy0">decoy0</a></td><td>GET</td><td>/</td><td>12:04:11</td><td>200</td></tr>
<tr><td><a href="/_profiler/decoy1">decoy1</a></td><td>POST</td><td>/login</td><td>12:03:58</td><td>302</td></tr></tbody></table>
<p>Symfony 5.4.21 | Environment: prod</p></div></body></html>
`},
	"laravel-telescope": {"application/json", `{"entries":[
{"id":"decoy-0000","type":"request","content":{"method":"GET","uri":"/api/health","response_status":200,"duration":7}},
{"id":"decoy-0001","type":"query","content":{"connection":"mysql","sql":"select * from users where id = ?","time":"1.42"}}],
"status":"enabled"}
`},
	"thinkphp": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>ThinkPHP</title></head>
<body><div class="error"><h1>Fatal error</h1>
<p>Call to undefined method think\App::invokefunction()</p>
<p class="file">File: /var/www/example/thinkphp/library/think/App.php  Line: 434</p>
<p class="version">ThinkPHP V5.0.24 { Fast &amp; Simple OOP PHP Framework }</p></div></body></html>
`},
	"phpunit-eval": {"text/plain; charset=utf-8", `PHP Parse error:  syntax error, unexpected end of file in /var/www/example/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php(1) : eval()'d code on line 1
`},
	"spring-gateway": {"application/json", `[{"route_id":"internal-billing","uri":"lb://billing","predicate":"Paths: [/billing/**]","order":0},
{"route_id":"admin-tools","uri":"http://10.0.9.4:8080","predicate":"Paths: [/admin-tools/**]","order":0},
{"route_id":"public-api","uri":"lb://api","predicate":"Paths: [/api/**]","order":10}]
`},

	// Files a traversal or a misconfigured server hands over. Each one
	// is what the probe expects to see, and nothing in it is real.
	"etc-passwd": {"text/plain; charset=utf-8", `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
deploy:x:1000:1000:Deploy Account:/home/deploy:/bin/bash
`},
	"firebase-config": {"application/javascript", `var firebaseConfig = {
  apiKey: "AIzaDecoyNotARealKey0000000000000000000",
  authDomain: "example-decoy.firebaseapp.com",
  databaseURL: "https://example-decoy.firebaseio.com",
  projectId: "example-decoy",
  storageBucket: "example-decoy.appspot.com",
  messagingSenderId: "000000000000",
  appId: "1:000000000000:web:0000000000000000000000"
};
firebase.initializeApp(firebaseConfig);
`},
	"wp-json-users": {"application/json", `[{"id":1,"name":"admin","slug":"admin","description":"","link":"https://www.example.com/author/admin/"},
{"id":4,"name":"editor","slug":"editor","description":"","link":"https://www.example.com/author/editor/"},
{"id":7,"name":"deploy","slug":"deploy","description":"Automation account","link":"https://www.example.com/author/deploy/"}]
`},
	"dockerfile": {"text/plain; charset=utf-8", `FROM node:18-alpine
WORKDIR /srv/app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV NODE_ENV=production
ENV API_BASE=https://api.internal.example
ARG BUILD_TOKEN=decoy-build-token-not-real
EXPOSE 3000
USER node
CMD ["node", "server.js"]
`},
	"rails-secrets": {"text/yaml; charset=utf-8", `development:
  secret_key_base: decoy0000000000000000000000000000000000000000000000000000000000
production:
  secret_key_base: decoy1111111111111111111111111111111111111111111111111111111111
  smtp_user_name: notifications@example.com
  smtp_password: decoy-not-a-real-password
  database_url: postgres://app:decoy-not-a-real-password@db.internal.example:5432/app
`},

	// Mail, messaging and remote access: the surfaces the SMTP, MQTT
	// and SSH listeners put on the network, which have their own
	// scanners and their own leaked-file habits.
	"roundcube": {"text/html; charset=utf-8", `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Roundcube Webmail :: Welcome to Roundcube Webmail</title>
<link rel="stylesheet" href="/skins/elastic/styles/styles.min.css"></head>
<body class="task-login"><div id="layout"><form name="form" method="post" action="/?_task=login">
<input type="hidden" name="_token" value="decoy0000000000000000000000000000">
<p><label for="rcmloginuser">Username</label><input name="_user" id="rcmloginuser" type="text" autocomplete="username"></p>
<p><label for="rcmloginpwd">Password</label><input name="_pass" id="rcmloginpwd" type="password" autocomplete="current-password"></p>
<p><button type="submit" id="rcmloginsubmit">Login</button></p>
</form><div id="login-footer">Roundcube Webmail 1.6.6</div></div></body></html>
`},
	"postfixadmin": {"text/html; charset=utf-8", `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Postfix Admin - Login</title></head>
<body><div id="login"><h1>Postfix Admin</h1>
<form method="post" action="/login.php">
<input type="hidden" name="token" value="decoy1111111111111111111111111111">
<p><label for="fUsername">Login (email)</label><input type="text" name="fUsername" id="fUsername"></p>
<p><label for="fPassword">Password</label><input type="password" name="fPassword" id="fPassword"></p>
<p><input type="submit" name="submit" value="Login"></p>
</form><p class="footer">Postfix Admin 3.3.13 &mdash; mail.example.com</p></div></body></html>
`},
	"smtp-config": {"text/plain; charset=utf-8", `# Postfix main.cf
myhostname = mail.example.com
mydomain = example.com
relayhost = [smtp.relay.example.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = static:relay@example.com:decoy-not-a-real-password
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = encrypt
smtpd_tls_cert_file = /etc/ssl/certs/mail.example.com.pem
smtpd_tls_key_file = /etc/ssl/private/mail.example.com.key
smtpd_sasl_auth_enable = yes
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination
mynetworks = 127.0.0.0/8 10.0.0.0/24
message_size_limit = 26214400
`},
	"dovecot-users": {"text/plain; charset=utf-8", `# dovecot passwd-file
postmaster@example.com:{SHA512-CRYPT}$6$decoy$0000000000000000000000000000000000000000000000000000000000000000000000000000000000000:5000:5000::/srv/vmail/example.com/postmaster::
noreply@example.com:{SHA512-CRYPT}$6$decoy$1111111111111111111111111111111111111111111111111111111111111111111111111111111111111:5000:5000::/srv/vmail/example.com/noreply::
backups@example.com:{PLAIN}decoy-not-a-real-password:5000:5000::/srv/vmail/example.com/backups::
`},
	"emqx-dashboard": {"text/html; charset=utf-8", `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>EMQX Dashboard</title>
<link rel="stylesheet" href="/static/css/app.css"></head>
<body><div id="app"><div class="login-box"><h2>EMQX Dashboard</h2>
<form method="post" action="/api/v5/login">
<p><label for="username">Username</label><input id="username" name="username" type="text" placeholder="admin"></p>
<p><label for="password">Password</label><input id="password" name="password" type="password"></p>
<p><button type="submit">Log In</button></p>
</form><p class="version">EMQX v5.4.1 &mdash; cluster mqtt@10.0.0.11</p></div></div></body></html>
`},
	"mosquitto-conf": {"text/plain; charset=utf-8", `# mosquitto.conf
listener 1883 0.0.0.0
protocol mqtt
listener 8883 0.0.0.0
protocol mqtt
certfile /etc/mosquitto/certs/mqtt.example.com.pem
keyfile /etc/mosquitto/certs/mqtt.example.com.key
allow_anonymous false
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/aclfile
max_packet_size 262144
persistence true
persistence_location /var/lib/mosquitto/
log_dest file /var/log/mosquitto/mosquitto.log
connection bridge-01
address mqtt-bridge.internal.example:8883
remote_username bridge
remote_password decoy-not-a-real-password
topic sensors/# both 0
`},
	"mqtt-clients": {"application/json", `{"data":[{"clientid":"gateway-01","username":"gateway","connected":true,"ip_address":"10.0.0.31","proto_name":"MQTT","proto_ver":5,"keepalive":60,"subscriptions_cnt":4},
{"clientid":"sensor-a17","username":"sensor","connected":true,"ip_address":"10.0.0.87","proto_name":"MQTT","proto_ver":4,"keepalive":30,"subscriptions_cnt":1},
{"clientid":"grafana-bridge","username":"bridge","connected":false,"ip_address":"10.0.0.19","proto_name":"MQTT","proto_ver":5,"keepalive":120,"subscriptions_cnt":12}],
"meta":{"count":3,"limit":100,"page":1}}
`},
	"teleport": {"text/html; charset=utf-8", `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Teleport</title>
<link rel="stylesheet" href="/web/app/app.css"></head>
<body><div id="app"></div>
<script id="teleport-config" type="application/json">{"proxyCluster":"teleport.example.com","authType":"local","secondFactor":"otp","canJoinSessions":true}</script>
<noscript>Teleport 14.3.0 requires JavaScript. Sign in at https://teleport.example.com/web/login</noscript>
</body></html>
`},
	"guacamole": {"text/html; charset=utf-8", `<!DOCTYPE html>
<html lang="en" ng-app="index"><head><meta charset="utf-8"><title>Apache Guacamole</title>
<link rel="stylesheet" href="/guacamole/app.css"></head>
<body><div class="login-ui"><form id="login-form" method="post" action="/guacamole/api/tokens">
<p><label for="username">Username</label><input id="username" name="username" type="text" autocorrect="off" autocapitalize="off"></p>
<p><label for="password">Password</label><input id="password" name="password" type="password"></p>
<p><input type="submit" name="login" value="Login"></p>
</form><div class="version">Apache Guacamole 1.5.4 &mdash; guacd 10.0.0.42:4822</div></div></body></html>
`},
	"authorized-keys": {"text/plain; charset=utf-8", `# /home/deploy/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRlY295LWtleS1ub3QtcmVhbC0wMDAwMDAwMDAw deploy@build01.example.com
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRlY295LWtleS1ub3QtcmVhbC0xMTExMTExMTEx ops@jump.example.com
command="/usr/local/bin/backup-receive",no-pty,no-port-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRlY295LWtleS1ub3QtcmVhbC0yMjIyMjIyMjIy backup@nas.example.com
`},
	"known-hosts": {"text/plain; charset=utf-8", `# /home/deploy/.ssh/known_hosts
jump.example.com,10.0.0.8 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRlY295LWhvc3Qta2V5LW5vdC1yZWFsLTAwMDAw
build01.example.com,10.0.0.21 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRlY295LWhvc3Qta2V5LW5vdC1yZWFsLTExMTEx
db01.internal.example,10.0.0.55 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRlY295LWhvc3Qta2V5LW5vdC1yZWFsLTIyMjIy
git.example.com,203.0.113.7 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRlY295LWhvc3Qta2V5LW5vdC1yZWFsLTMzMzMz
`},
	"sshd-config": {"text/plain; charset=utf-8", `# /etc/ssh/sshd_config
Port 22
ListenAddress 10.0.0.8
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
AllowTcpForwarding yes
PermitTunnel no
X11Forwarding no
ClientAliveInterval 300
Subsystem sftp internal-sftp
Match Group sftponly
  ChrootDirectory /srv/sftp/%u
  ForceCommand internal-sftp
  AllowTcpForwarding no
`},
	"openvpn-config": {"text/plain; charset=utf-8", `client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
ZGVjb3kgY2VydGlmaWNhdGUsIG5vdCByZWFsLCBmb3IgYSBob25leXBvdCBvbmx5
-----END CERTIFICATE-----
</ca>
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
6465636f79206b65792c206e6f74207265616c2c20666f72206120686f6e6579
-----END OpenVPN Static key V1-----
</tls-crypt>
`},
	"wireguard-conf": {"text/plain; charset=utf-8", `# /etc/wireguard/wg0.conf
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = ZGVjb3kta2V5LW5vdC1yZWFsLWRvLW5vdC11c2UtMDAwMA=
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT

[Peer]
# ops laptop
PublicKey = ZGVjb3ktcHVibGljLW5vdC1yZWFsLTExMTExMTExMTExMTE=
AllowedIPs = 10.0.0.11/32

[Peer]
# build runner
PublicKey = ZGVjb3ktcHVibGljLW5vdC1yZWFsLTIyMjIyMjIyMjIyMjI=
AllowedIPs = 10.0.0.12/32
`},
	"filezilla-sites": {"application/xml", `<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.66.4" platform="linux">
  <Servers>
    <Server>
      <Host>sftp.example.com</Host>
      <Port>22</Port>
      <Protocol>1</Protocol>
      <Type>0</Type>
      <User>deploy</User>
      <Pass encoding="base64">ZGVjb3ktbm90LWEtcmVhbC1wYXNzd29yZA==</Pass>
      <Logontype>1</Logontype>
      <Name>production sftp</Name>
    </Server>
    <Server>
      <Host>backup.internal.example</Host>
      <Port>2222</Port>
      <Protocol>1</Protocol>
      <User>backup</User>
      <Pass encoding="base64">ZGVjb3ktbm90LWEtcmVhbC1wYXNzd29yZA==</Pass>
      <Logontype>1</Logontype>
      <Name>backup</Name>
    </Server>
  </Servers>
</FileZilla3>
`},
	"winscp-ini": {"text/plain; charset=utf-8", `[Configuration\Interface]
PathInCaption=1

[Sessions\deploy%40sftp.example.com]
HostName=sftp.example.com
PortNumber=22
UserName=deploy
Password=decoy-not-a-real-password
FSProtocol=5
RemoteDirectory=/srv/www

[Sessions\backup%40backup.internal.example]
HostName=backup.internal.example
PortNumber=2222
UserName=backup
Password=decoy-not-a-real-password
FSProtocol=5
`},
	"vsftpd-conf": {"text/plain; charset=utf-8", `# /etc/vsftpd.conf
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
ssl_enable=YES
force_local_data_ssl=YES
force_local_logins_ssl=YES
rsa_cert_file=/etc/ssl/certs/ftp.example.com.pem
rsa_private_key_file=/etc/ssl/private/ftp.example.com.key
pasv_min_port=40000
pasv_max_port=40100
pasv_address=203.0.113.20
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
`},
	"rsync-modules": {"text/plain; charset=utf-8", `# rsyncd.conf on backup.internal.example
uid = rsync
gid = rsync
use chroot = yes
max connections = 8
log file = /var/log/rsyncd.log

[backups]
path = /srv/backups
comment = nightly database dumps
read only = no
auth users = backup
secrets file = /etc/rsyncd.secrets
hosts allow = 10.0.0.0/24

[releases]
path = /srv/releases
comment = build artefacts
read only = yes
list = yes
`},
	"webmin": {"text/html; charset=utf-8", `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Login to Webmin</title>
<link rel="stylesheet" href="/unauthenticated/css/bundle.min.css"></head>
<body class="session_login"><div class="login-container"><form action="/session_login.cgi" method="post">
<input type="hidden" name="page" value="/">
<h1>Login to Webmin</h1>
<p>You must enter a username and password to login to the server on 10.0.0.9.</p>
<p><label for="user">Username</label><input name="user" id="user" type="text"></p>
<p><label for="pass">Password</label><input name="pass" id="pass" type="password"></p>
<p><input type="submit" value="Sign in"></p>
</form><div class="version">Webmin 2.021</div></div></body></html>
`},
	"cockpit": {"text/html; charset=utf-8", `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Cockpit</title>
<link href="/cockpit/static/login.css" rel="stylesheet"></head>
<body class="login-pf"><div id="login"><h1 id="brand">db01.internal.example</h1>
<form id="login-form" action="/cockpit/login" method="post">
<p><label for="login-user-input">User name</label><input id="login-user-input" name="user" type="text" autocomplete="username"></p>
<p><label for="login-password-input">Password</label><input id="login-password-input" name="password" type="password" autocomplete="current-password"></p>
<p><button id="login-button" type="submit">Log In</button></p>
</form><div id="server-name">Cockpit 309 on Debian GNU/Linux 12</div></div></body></html>
`},
	"mail-queue": {"application/json", `{"queue":[{"queue_id":"4Zx8Kp1mN2z","sender":"noreply@example.com","recipients":["ops@example.com"],"size":8412,"arrival":"2026-03-04T08:11:02Z","status":"deferred","reason":"connect to mx.partner.example[203.0.113.44]:25: Connection timed out"},
{"queue_id":"4Zx8Kp3rT9q","sender":"billing@example.com","recipients":["accounts@partner.example"],"size":51204,"arrival":"2026-03-04T08:19:44Z","status":"active","reason":""}],
"summary":{"active":1,"deferred":1,"hold":0,"total_bytes":59616}}
`},
	"sftp-audit": {"text/plain; charset=utf-8", `2026-03-04T08:02:11Z sftp-server[41221]: session opened for local user deploy from [10.0.0.31]
2026-03-04T08:02:11Z sftp-server[41221]: opendir "/srv/www/releases"
2026-03-04T08:02:12Z sftp-server[41221]: open "/srv/www/releases/app-2026.03.1.tar.gz" flags READ mode 0666
2026-03-04T08:02:19Z sftp-server[41221]: close "/srv/www/releases/app-2026.03.1.tar.gz" bytes read 48210433 written 0
2026-03-04T08:02:19Z sftp-server[41221]: session closed for local user deploy from [10.0.0.31]
2026-03-04T08:14:57Z sftp-server[41398]: session opened for local user backup from [10.0.0.55]
2026-03-04T08:14:58Z sftp-server[41398]: open "/srv/backups/db-2026-03-04.sql.gz" flags WRITE,CREATE,TRUNCATE mode 0600
`},
	"mqtt-acl": {"text/plain; charset=utf-8", `# /etc/mosquitto/aclfile
user gateway
topic readwrite sensors/#
topic read estate/announcements

user sensor
topic write sensors/%u/telemetry
topic read sensors/%u/commands

user bridge
topic readwrite #

pattern read $SYS/broker/clients/#
`},
}

// readBounded reads a file of at most limit bytes.
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // operator supplied path from the configuration
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file larger than the bound")
	}
	return b, nil
}

// Decoys implements proxy.PlaneStatus: the built-in decoys, by name.
func (s *engine) Decoys() []string { return DecoyNames() }

// DecoyNames lists the built-in decoys.
func DecoyNames() []string {
	names := make([]string, 0, len(decoys))
	for n := range decoys {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// mark is a client that hit a honeypot. It is the plane's own record;
// proxy.Mark is what the management view is given, without the peer
// attribution, which is this table's bookkeeping rather than anybody's
// business outside it.
type mark struct {
	Address string
	Route   string
	Hits    int
	First   time.Time
	Last    time.Time
	Expires time.Time
	// peer is the cluster peer that sent this mark, or "" when this node
	// made it. Only that peer may withdraw it.
	peer string
}

// status is the management view of one mark.
func (m *mark) status() proxy.Mark {
	return proxy.Mark{Address: m.Address, Route: m.Route, Hits: m.Hits,
		First: m.First, Last: m.Last, Expires: m.Expires}
}

const maxMarks = 65536

// maxPeerMarks reserves most of the table for what this node saw
// itself. A peer's marks are useful, but a peer that sends 65,000 of
// them must not leave this node unable to record its own honeypot hits,
// which is the detection the table exists for.
const maxPeerMarks = maxMarks / 4

// marks remembers clients that touched a honeypot so that their later
// requests on other routes are labelled. It is bounded and sweeps expired
// entries lazily.
type marks struct {
	mu sync.Mutex
	m  map[netip.Addr]*mark
	// peers counts live entries per peer so that one peer cannot take
	// the whole table; peerFull reports when one hits its share.
	peers    map[string]int
	full     bound.Notice
	peerFull bound.Notice
}

// Dropped counts marks refused because the table was full of live ones.
func (m *marks) Dropped() uint64 { return m.full.Total() }

func newMarks() *marks { return &marks{m: map[netip.Addr]*mark{}, peers: map[string]int{}} }

// add records a mark this node made. peer is "" for a local hit and the
// peer's name for one that arrived over the cluster.
func (m *marks) add(ip netip.Addr, route string, ttl time.Duration, now time.Time) {
	m.addFrom(ip, route, ttl, now, "")
}

func (m *marks) addFrom(ip netip.Addr, route string, ttl time.Duration, now time.Time, peer string) {
	if !ip.IsValid() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if peer != "" && m.peers[peer] >= maxPeerMarks {
		if _, known := m.m[ip]; !known {
			m.peerFull.Hit(nil, "a peer's share of the honeypot mark table is full; its new marks are dropped",
				"table", "honeypot_marks", "peer", peer, "max_per_peer", maxPeerMarks)
			return
		}
	}
	if e, ok := m.m[ip]; ok {
		e.Hits++
		e.Last = now
		e.Route = route
		e.Expires = now.Add(ttl)
		return
	}
	if len(m.m) >= maxMarks {
		m.sweep(now)
		if len(m.m) >= maxMarks {
			m.full.Hit(nil, "honeypot mark table full; new marks are dropped until marks expire", "table", "honeypot_marks", "max", maxMarks)
			return // full of live marks: keep what we have rather than grow
		}
	}
	m.m[ip] = &mark{Address: ip.String(), Route: route, Hits: 1, First: now, Last: now, Expires: now.Add(ttl), peer: peer}
	if peer != "" {
		m.peers[peer]++
	}
}

func (m *marks) sweep(now time.Time) {
	for ip, e := range m.m {
		if now.After(e.Expires) {
			m.dropLocked(ip, e)
		}
	}
}

func (m *marks) dropLocked(ip netip.Addr, e *mark) {
	delete(m.m, ip)
	if e.peer != "" {
		if m.peers[e.peer]--; m.peers[e.peer] <= 0 {
			delete(m.peers, e.peer)
		}
	}
}

func (m *marks) marked(ip netip.Addr, now time.Time) bool {
	if !ip.IsValid() {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.m[ip]
	if !ok {
		return false
	}
	if now.After(e.Expires) {
		m.dropLocked(ip, e)
		return false
	}
	return true
}

func (m *marks) list(now time.Time) []proxy.Mark {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep(now)
	out := make([]proxy.Mark, 0, len(m.m))
	for _, e := range m.m {
		out = append(out, e.status())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out
}

// remove withdraws a mark. peer is "" for an operator or a local
// decision, which may withdraw anything; a cluster peer may withdraw
// only a mark it sent itself, or a rogue node could clear the marks
// every other node made for its own clients.
func (m *marks) remove(ip netip.Addr) bool { return m.removeFrom(ip, "") }

func (m *marks) removeFrom(ip netip.Addr, peer string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.m[ip]
	if !ok {
		return false
	}
	if peer != "" && e.peer != peer {
		return false
	}
	m.dropLocked(ip, e)
	return true
}

// HoneypotMarks lists clients currently marked by a honeypot, most recent
// first.
func (s *engine) HoneypotMarks() []proxy.Mark { return s.marks.list(time.Now()) }

// HoneypotMarksDropped counts marks refused by a full table.
func (s *engine) HoneypotMarksDropped() uint64 { return s.marks.Dropped() }

// UnmarkHoneypot forgets a marked client.
func (s *engine) UnmarkHoneypot(ip netip.Addr) bool {
	ok := s.marks.remove(ip.Unmap())
	if ok {
		s.publishEvent(cluster.Event{Kind: eventHoneypotUnmark, Key: ip.Unmap().String(), Until: time.Now().Add(time.Minute)})
	}
	return ok
}

// thirdPartyInduced reports a request a browser made because another
// origin asked it to: a sub-resource, a prefetch or a navigation from a
// link on another site. Browsers send Sec-Fetch-Site on every request;
// a client that sends none (a scanner, a script) is never treated as
// induced, and neither is a typed URL (none) or a same-origin fetch.
func thirdPartyInduced(r *http.Request) bool {
	if r.Header.Get("Sec-Purpose") != "" || strings.EqualFold(r.Header.Get("Purpose"), "prefetch") {
		return true
	}
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Site")) {
	case "cross-site", "same-site":
		return true
	}
	return false
}

// honeypot serves a decoy. The client is recorded as a security event,
// marked for the configured time and counted towards the honeypot ban
// reason; the response itself looks like the real thing. An optional
// delay holds the connection in a tarpit slot, never in a concurrency
// slot.
func (s *engine) honeypot(rw *responseWriter, r *http.Request, st *reqState, cr *compiledRoute, release func()) {
	hp := cr.cfg.Honeypot
	now := time.Now()
	s.stats.HoneypotHits.Add(1)
	st.denied = "honeypot"
	s.logs.SecurityEvent(r.Context(), "honeypot", "honeypot",
		"request_id", st.id, "client_ip", st.clientIP.String(), "method", r.Method,
		"host", r.Host, "path", r.URL.Path, "query_len", len(r.URL.RawQuery), "route", st.route,
		"user_agent", r.UserAgent(), "referer", r.Referer(), "decoy", hp.Decoy)
	// A browser that fetched the decoy because another site told it to (an
	// <img> in a forum post, a prefetch, a planted link) says nothing about
	// the person behind it, so the decoy is served but nobody is marked or
	// banned for it. A scanner sends no Sec-Fetch-Site at all and is still
	// counted.
	if induced := thirdPartyInduced(r); induced {
		st.extra = append(st.extra, "honeypot_induced", true)
	} else {
		// A honeypot served honestly — robots.txt, sitemap.xml — marks
		// nobody: reading it is what a crawler is meant to do. Asking
		// for what it names is the part that says something.
		if d := hp.MarkFor(); d > 0 {
			s.marks.add(st.clientIP, cr.cfg.Name, d, now)
			s.publishEvent(cluster.Event{Kind: eventHoneypotMark, Key: st.clientIP.String(), Route: cr.cfg.Name, Until: now.Add(d)})
			if bl := s.host.Bans(); bl != nil {
				bl.Observe(st.clientIP, "honeypot")
			}
		}
	}
	rw.Header().Set("X-Robots-Tag", "noindex, nofollow")
	if hp.Delay > 0 {
		release() // a held decoy must not occupy a request slot (see max_tarpits)
		if tpRelease, ok := s.tarpits.Acquire(); ok {
			select {
			case <-time.After(hp.Delay.D()):
			case <-r.Context().Done():
				tpRelease()
				s.stats.ClientAborts.Add(1)
				rw.status = 499
				rw.wrote = true
				return
			}
			tpRelease()
		} else {
			s.stats.TarpitOverflow.Add(1)
		}
	}
	h := rw.Header()
	h.Set("Content-Type", cr.honeypotType)
	h.Set("Cache-Control", "no-store")
	cr.respOps.apply(h, &tvars{r: r, st: st})
	rw.WriteHeader(hp.Status)
	if r.Method != http.MethodHead {
		_, _ = rw.Write(cr.honeypotBody)
	}
}
