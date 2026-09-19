# RPM packaging for xproxy. Built from the tarball that `make dist` produces
# (sources plus vendored modules, no network needed):
#
#   make rpm            # builds SRPM and RPMs under ./rpmbuild
#
# Packages:
#   xproxy          data plane, xproxyctl, units, sysctl profile, logrotate,
#                   sysusers, example configuration
#   xproxy-admin    web GUI, its unit and polkit rule
#   xproxy-selinux  SELinux policy module (noarch)

%global selinuxtype targeted
%global modulename  xproxy
%global goipath     github.com/rom/xproxy
%global gitcommit   %{?xproxy_commit}%{!?xproxy_commit:unknown}

Name:           xproxy
Version:        %{?xproxy_version}%{!?xproxy_version:0.0.0}
Release:        %{?xproxy_release}%{!?xproxy_release:1}%{?dist}
Summary:        Security focused reverse proxy, load balancer and web application firewall
License:        Proprietary
URL:            https://github.com/rom/xproxy
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.25
BuildRequires:  make
BuildRequires:  systemd-rpm-macros
Requires:       systemd
Requires(pre):  shadow-utils
%{?systemd_requires}
Recommends:     %{name}-selinux = %{version}-%{release}

# The binaries are static and carry no ELF dependencies.
%global debug_package %{nil}
%global _missing_build_ids_terminate_build 0

%description
Xproxy is an HTTP/1.1, HTTP/2 and HTTP/3 reverse proxy, load balancer and
web application firewall written in Go for Fedora Linux. It runs
unprivileged under a hardened systemd unit with socket activation, is
confined by SELinux, and is managed over a local Unix socket by xproxyctl
(command line and terminal UI) and xproxy-admin (web GUI).

%package        admin
Summary:        Web GUI for xproxy
Requires:       %{name} = %{version}-%{release}
Requires:       polkit

%description    admin
xproxy-admin serves the browser interface for xproxy on a loopback address
or a mutual TLS listener, with viewer and operator roles, configuration
editing with validation, graphs and live logs. It runs as its own user and
talks to the management socket of the data plane.

%package        selinux
Summary:        SELinux policy module for xproxy
BuildArch:      noarch
BuildRequires:  selinux-policy-devel
BuildRequires:  bzip2
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
%{?selinux_requires}

%description    selinux
SELinux policy confining xproxy (xproxy_t) and xproxy-admin
(xproxy_admin_t) under the targeted policy, with the file, port and unit
types and the booleans xproxy_connect_any and xproxy_admin_manage_service.

%prep
%autosetup -n %{name}-%{version}

%build
export GOTOOLCHAIN=local
export GOFLAGS=-mod=vendor
make build GOMODFLAG=-mod=vendor VERSION=%{version}-%{release} COMMIT=%{gitcommit} DATE=$(date -u -d @${SOURCE_DATE_EPOCH:-$(date +%%s)} +%%Y-%%m-%%dT%%H:%%M:%%SZ)
( cd deploy/selinux && make -f %{_datadir}/selinux/devel/Makefile %{modulename}.pp && bzip2 -9 %{modulename}.pp )

%install
install -D -m 0755 bin/xproxy        %{buildroot}%{_bindir}/xproxy
install -D -m 0755 bin/xproxyctl     %{buildroot}%{_bindir}/xproxyctl
install -D -m 0755 bin/xproxy-admin  %{buildroot}%{_bindir}/xproxy-admin

# Units, sysctl, logrotate, sysusers, polkit. The shipped files reference
# /usr/local/bin for source installs; rewrite for the packaged layout.
for u in xproxy.service xproxy.socket xproxy-https.socket xproxy-h3.socket xproxy-admin.service; do
  sed 's|/usr/local/bin|%{_bindir}|g' deploy/systemd/$u > $u.tmp
  install -D -m 0644 $u.tmp %{buildroot}%{_unitdir}/$u
done
sed 's|/usr/local/bin|%{_bindir}|g' deploy/logrotate/xproxy > logrotate.tmp
install -D -m 0644 logrotate.tmp           %{buildroot}%{_sysconfdir}/logrotate.d/xproxy
install -D -m 0644 deploy/sysctl/90-xproxy.conf  %{buildroot}%{_sysctldir}/90-xproxy.conf
install -D -m 0644 deploy/sysusers/xproxy.conf   %{buildroot}%{_sysusersdir}/xproxy.conf
install -D -m 0644 deploy/polkit/50-xproxy-admin.rules %{buildroot}%{_datadir}/polkit-1/rules.d/50-xproxy-admin.rules

# Configuration and directories. systemd also creates the runtime, log and
# state directories on first start; owning them here fixes ownership and
# labels at install time.
install -d -m 0750 %{buildroot}%{_sysconfdir}/xproxy
install -D -m 0640 deploy/config/xproxy.yaml %{buildroot}%{_sysconfdir}/xproxy/xproxy.yaml
install -d -m 0750 %{buildroot}%{_localstatedir}/log/xproxy
install -d -m 0700 %{buildroot}%{_sharedstatedir}/xproxy

# Documentation, manual pages, configuration schema and shell completion.
install -d -m 0755 %{buildroot}%{_docdir}/%{name}
install -m 0644 README.md docs/*.md %{buildroot}%{_docdir}/%{name}/
install -D -m 0644 docs/man/xproxy.8      %{buildroot}%{_mandir}/man8/xproxy.8
install -D -m 0644 docs/man/xproxyctl.8   %{buildroot}%{_mandir}/man8/xproxyctl.8
install -D -m 0644 docs/man/xproxy.yaml.5 %{buildroot}%{_mandir}/man5/xproxy.yaml.5
install -D -m 0644 internal/config/schema/xproxy.schema.json %{buildroot}%{_datadir}/xproxy/xproxy.schema.json
install -D -m 0644 deploy/grafana/xproxy-overview.json %{buildroot}%{_datadir}/xproxy/grafana/xproxy-overview.json
install -D -m 0644 deploy/grafana/xproxy-security.json %{buildroot}%{_datadir}/xproxy/grafana/xproxy-security.json
install -D -m 0644 deploy/grafana/README.md %{buildroot}%{_datadir}/xproxy/grafana/README.md
install -D -m 0644 deploy/prometheus/xproxy-alerts.yaml %{buildroot}%{_datadir}/xproxy/prometheus/xproxy-alerts.yaml
install -d -m 0755 %{buildroot}%{_datadir}/bash-completion/completions %{buildroot}%{_datadir}/zsh/site-functions %{buildroot}%{_datadir}/fish/vendor_completions.d
bin/xproxyctl completion bash > %{buildroot}%{_datadir}/bash-completion/completions/xproxyctl
bin/xproxyctl completion zsh  > %{buildroot}%{_datadir}/zsh/site-functions/_xproxyctl
bin/xproxyctl completion fish > %{buildroot}%{_datadir}/fish/vendor_completions.d/xproxyctl.fish

# SELinux module and interface file for other policies.
install -D -m 0644 deploy/selinux/%{modulename}.pp.bz2 %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
install -D -m 0644 deploy/selinux/%{modulename}.if     %{buildroot}%{_datadir}/selinux/devel/include/contrib/%{modulename}.if

%check
# The vendored build must be self-contained: no module downloads.
GOFLAGS=-mod=vendor GOTOOLCHAIN=local go vet ./cmd/... >/dev/null

%pre
%{?sysusers_create_compat:%sysusers_create_compat deploy/sysusers/xproxy.conf}

%post
%systemd_post xproxy.service xproxy.socket xproxy-https.socket xproxy-h3.socket
sysctl -q -p %{_sysctldir}/90-xproxy.conf >/dev/null 2>&1 || :

%preun
%systemd_preun xproxy.service xproxy.socket xproxy-https.socket xproxy-h3.socket

%postun
%systemd_postun_with_restart xproxy.service

%post admin
%systemd_post xproxy-admin.service

%preun admin
%systemd_preun xproxy-admin.service

%postun admin
%systemd_postun_with_restart xproxy-admin.service

%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2

%postun selinux
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} %{modulename}
fi

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}

%files
%license LICENSE
%doc %{_docdir}/%{name}
%{_bindir}/xproxy
%{_bindir}/xproxyctl
%{_mandir}/man8/xproxy.8*
%{_mandir}/man8/xproxyctl.8*
%{_mandir}/man5/xproxy.yaml.5*
%dir %{_datadir}/xproxy
%{_datadir}/xproxy/xproxy.schema.json
%{_datadir}/xproxy/grafana
%{_datadir}/xproxy/prometheus
%{_datadir}/bash-completion/completions/xproxyctl
%{_datadir}/zsh/site-functions/_xproxyctl
%{_datadir}/fish/vendor_completions.d/xproxyctl.fish
%{_unitdir}/xproxy.service
%{_unitdir}/xproxy.socket
%{_unitdir}/xproxy-https.socket
%{_unitdir}/xproxy-h3.socket
%{_sysctldir}/90-xproxy.conf
%{_sysusersdir}/xproxy.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/xproxy
%dir %attr(0750,root,xproxy) %{_sysconfdir}/xproxy
%config(noreplace) %attr(0640,root,xproxy) %{_sysconfdir}/xproxy/xproxy.yaml
%dir %attr(0750,xproxy,xproxy) %{_localstatedir}/log/xproxy
%dir %attr(0700,xproxy,xproxy) %{_sharedstatedir}/xproxy

%files admin
%{_bindir}/xproxy-admin
%{_unitdir}/xproxy-admin.service
%{_datadir}/polkit-1/rules.d/50-xproxy-admin.rules

%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
%{_datadir}/selinux/devel/include/contrib/%{modulename}.if
%ghost %verify(not md5 size mode mtime) %{_sharedstatedir}/selinux/%{selinuxtype}/active/modules/200/%{modulename}

%changelog
* Fri Sep 18 2026 Sysctl AB <hostmaster@sysctl.se> - 1.0.0-1
- First release (see RELEASE_NOTES_1.0.md).

* Fri Sep 18 2026 Sysctl AB <hostmaster@sysctl.se> - 0.9.0-1
- Initial packaging: data plane, CLI, web GUI, SELinux policy module.
