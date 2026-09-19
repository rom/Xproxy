# Grafana dashboards and Prometheus alert rules

Shipped with the product and installed under `/usr/share/xproxy/grafana`
and `/usr/share/xproxy/prometheus` (`make install`, the RPM).

| File | Content |
|------|---------|
| `xproxy-overview.json` | Traffic, status classes, latency percentiles (request and upstream time to first byte), upstream failures and healthy endpoints, per route rates and p99, bytes, load and shedding, in flight and queued requests, cache, certificate expiry, reloads, a node table |
| `xproxy-security.json` | Denied requests by reason, WAF blocks and detect mode hits, bans, challenges, rate limit decisions per policy, filter denials, connections rejected at accept, honeypot and ICAP results, forward proxy policy, DNS filtering, log delivery per sink, cluster peers |
| `../prometheus/xproxy-alerts.yaml` | Alerting rules in three groups: availability (down, no healthy endpoint, unhealthy endpoint, circuit open, 5xx ratio, latency, shedding, queue refusals), operations (failed reload, certificate expiry at 14 and 3 days, log drops and write errors, cluster peer down, ICAP unreachable) and security (attack surge against the hourly baseline, WAF block spike, ban wave, honeypot activity, saturated rate limit policy) |

Import a dashboard with Dashboards > New > Import and pick the
Prometheus data source when asked; both dashboards share an `instance`
variable (from `xproxy_build_info`) and link to each other. Load the
alert rules with `rule_files` in `prometheus.yml`, or import them as
Grafana managed rules. The scrape job should match `.*xproxy.*` for the
`XproxyDown` rule or the expression adjusted.

Every expression uses only families the exposition documents in
`docs/CONFIG.md` (`metrics`), and `test/observability` checks that each
metric named in these files is one the proxy exports, so the assets
cannot drift from the binary.

```yaml
scrape_configs:
  - job_name: xproxy
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/xproxy-metrics-ca.pem
      cert_file: /etc/prometheus/monitoring.pem
      key_file: /etc/prometheus/monitoring-key.pem
    static_configs:
      - targets: ["edge1.example.internal:9100", "edge2.example.internal:9100"]
rule_files:
  - /usr/share/xproxy/prometheus/xproxy-alerts.yaml
```
