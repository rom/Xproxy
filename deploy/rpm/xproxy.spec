# RPM packaging for xproxy. Built from the tarball that `make dist` produces
# (sources plus vendored modules, no network needed):
#
#   make rpm            # builds SRPM and RPMs under ./rpmbuild
#
# Packages:
#   xproxy          edge data plane, xproxyctl, units, sysctl profile,
#                   logrotate, sysusers, tmpfiles, example configuration
#   xproxy-xgate    gate daemon (interactive access by people)
#   xproxy-xrelay   relay daemon (the protocols services speak)
#   xproxy-xot      OT daemon (the protocols the plant speaks)
#   xproxy-signer   the process that holds the private keys instead
#   xproxy-admin    web GUI, its unit and polkit rule
#   xproxy-selinux  SELinux policy module (noarch)
#
# The daemons share one module, one configuration format and
# /etc/xproxy, which belongs to the xproxy-config group because no one
# of them can own what all of them read.

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

BuildRequires:  golang >= 1.26
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

%package        xgate
Summary:        Gate daemon for xproxy: interactive access by people
Requires:       %{name} = %{version}-%{release}
%{?systemd_requires}

%description    xgate
xgate serves the protocols people use to reach a machine directly -- the
SSH and SFTP bastion -- with per-principal policy, session recording and
an optional second factor. It runs as its own user under its own
hardened unit, reads its own file in /etc/xproxy, and shares the
estate's upstreams, bans and rate limits with its siblings over a local
cluster socket.

%package        xrelay
Summary:        Relay daemon for xproxy: machine to machine protocols
Requires:       %{name} = %{version}-%{release}
%{?systemd_requires}

%description    xrelay
xrelay serves the protocols services speak to each other -- SMTP and
submission, FTP, LDAP, the database wire protocols and AMQP, and MQTT,
syslog, SNMP, TFTP, DHCP and the time gateway where a listener does not
hand them to xot -- with the same policy, logging and management surface
as its siblings. It runs as its own user under its own hardened unit and
reads its own file in /etc/xproxy.

%package        xot
Summary:        OT daemon for xproxy: the protocols the plant speaks
Requires:       %{name} = %{version}-%{release}
%{?systemd_requires}

%description    xot
xot serves the control protocols -- Modbus, IEC 60870-5-104, S7,
IEC 61850 MMS, BACnet/IP, OPC UA and CoAP -- and the protocols the field
equipment itself speaks: SNMP, TFTP, DHCP, syslog, the NTP and NTS time
gateway, and MQTT for Sparkplug B telemetry. It is a package of its own
because it is a binary of its own: there is no mail parser, no FTP, no
directory and no database wire protocol in it, which is what a proxy at
level 3.5 between a process network and everything else should be able
to say. It
runs as its own user under its own hardened unit and reads its own file
in /etc/xproxy.
.
It also carries the behaviour packs, in %{_datadir}/xproxy/packs: signed,
versioned detection documents that say a shape of events from one actor inside
one window is one MITRE ATT&CK for ICS technique. They ship unsigned, because a
private key in a package is not one: sign the directory with
`xproxyctl packs sign` and name the public half in the `packs.keys` list.

%package        signer
Summary:        Signing helper for xproxy: the process that holds the private keys
Requires:       %{name} = %{version}-%{release}
%{?systemd_requires}

%description    signer
xsigner holds the TLS private keys so the proxies do not have to: they send a
digest over a Unix socket and get a signature back, and the key never crosses
the socket. Anything that can read a proxy's memory -- a core dump, a debugger,
a bug -- gets nothing, because there is nothing there to get.

It is also where cgo belongs: a PKCS#11 module is a vendor C library and the
daemons are built without cgo on purpose, so an HSM, a TPM or a smartcard is
reached from here rather than from the process that terminates TLS. This build
serves keys it reads as PEM from a file, the environment or a vault; the
protocol is documented in SIGNER.md so a helper for anything else can be
written against it.

It runs as its own user, with no network at all under the shipped unit, and its
socket's permissions are its authentication.

%package        admin
Summary:        Web GUI for xproxy
Requires:       %{name} = %{version}-%{release}
Requires:       polkit

%description    admin
xproxy-admin serves the browser interface for xproxy on a loopback address
or a mutual TLS listener, with viewer and operator roles, configuration
editing with validation, graphs and live logs. It runs as its own user and
talks to the management socket of the data plane.

%package        fleet
Summary:        Fleet controller for xproxy nodes
Requires:       %{name} = %{version}-%{release}

%description    fleet
xproxy-fleet serves every xproxy node its configuration bundle over
mutual TLS and collects the nodes' status. Editing the files under
/var/lib/xproxy-fleet is the push; agents apply a changed bundle within
seconds and report back.

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
# DATE is not passed: the tarball has no git metadata, so the Makefile takes
# the date from SOURCE_DATE_EPOCH, which rpmbuild sets from the changelog --
# which is what makes the binaries in a rebuilt package byte-identical. This
# used to convert the epoch here with `date -d @N`, duplicating the Makefile
# and falling back to the wall clock, which would have made a package built
# without SOURCE_DATE_EPOCH unreproducible for the one reason that matters.
make build GOMODFLAG=-mod=vendor VERSION=%{version}-%{release} COMMIT=%{gitcommit}
( cd deploy/selinux && make -f %{_datadir}/selinux/devel/Makefile %{modulename}.pp && bzip2 -9 %{modulename}.pp )

%install
install -D -m 0755 bin/xproxy        %{buildroot}%{_bindir}/xproxy
install -D -m 0755 bin/xgate         %{buildroot}%{_bindir}/xgate
install -D -m 0755 bin/xrelay        %{buildroot}%{_bindir}/xrelay
install -D -m 0755 bin/xot           %{buildroot}%{_bindir}/xot
install -D -m 0755 bin/xproxyctl     %{buildroot}%{_bindir}/xproxyctl
install -D -m 0755 bin/xproxy-replay %{buildroot}%{_bindir}/xproxy-replay
%{_bindir}/xproxy-simulate
install -D -m 0755 bin/xproxy-simulate %{buildroot}%{_bindir}/xproxy-simulate
install -D -m 0755 bin/xproxy-admin  %{buildroot}%{_bindir}/xproxy-admin
install -D -m 0755 bin/xproxy-fleet  %{buildroot}%{_bindir}/xproxy-fleet
install -D -m 0755 bin/xsigner       %{buildroot}%{_bindir}/xsigner
install -d -m 0750 %{buildroot}%{_sharedstatedir}/xproxy-fleet

# Units, sysctl, logrotate, sysusers, polkit. The shipped files reference
# /usr/local/bin for source installs; rewrite for the packaged layout.
for u in xproxy.service xproxy.socket xproxy-https.socket xproxy-h3.socket \
         xgate.service xgate.socket xrelay.service xrelay.socket \
         xot.service xot.socket \
         xproxy-admin.service xproxy-fleet.service xsigner.service; do
  sed 's|/usr/local/bin|%{_bindir}|g' deploy/systemd/$u > $u.tmp
  install -D -m 0644 $u.tmp %{buildroot}%{_unitdir}/$u
done
for l in xproxy xgate xrelay xot; do
  sed 's|/usr/local/bin|%{_bindir}|g' deploy/logrotate/$l > logrotate.$l.tmp
  install -D -m 0644 logrotate.$l.tmp      %{buildroot}%{_sysconfdir}/logrotate.d/$l
done
install -D -m 0644 deploy/sysctl/90-xproxy.conf  %{buildroot}%{_sysctldir}/90-xproxy.conf
install -D -m 0644 deploy/sysusers/xproxy.conf   %{buildroot}%{_sysusersdir}/xproxy.conf
install -D -m 0644 deploy/tmpfiles/xproxy-config.conf  %{buildroot}%{_tmpfilesdir}/xproxy-config.conf
install -D -m 0644 deploy/tmpfiles/xproxy-cluster.conf %{buildroot}%{_tmpfilesdir}/xproxy-cluster.conf
install -D -m 0644 deploy/tmpfiles/xsigner.conf        %{buildroot}%{_tmpfilesdir}/xsigner.conf
install -D -m 0644 deploy/polkit/50-xproxy-admin.rules %{buildroot}%{_datadir}/polkit-1/rules.d/50-xproxy-admin.rules

# Configuration and directories. systemd also creates the runtime, log and
# state directories on first start; owning them here fixes ownership and
# labels at install time.
install -d -m 0750 %{buildroot}%{_sysconfdir}/xproxy
install -D -m 0640 deploy/config/xproxy.yaml %{buildroot}%{_sysconfdir}/xproxy/xproxy.yaml
install -D -m 0640 deploy/config/xgate.yaml  %{buildroot}%{_sysconfdir}/xproxy/xgate.yaml
install -D -m 0640 deploy/config/xrelay.yaml %{buildroot}%{_sysconfdir}/xproxy/xrelay.yaml
install -D -m 0640 deploy/config/xot.yaml    %{buildroot}%{_sysconfdir}/xproxy/xot.yaml
# The signer's configuration is NOT under /etc/xproxy: that directory is
# readable by the xproxy-config group, which is the proxy daemons, and
# the point of this process is that they cannot read what it reads.
install -d -m 0750 %{buildroot}%{_sysconfdir}/xsigner
install -d -m 0700 %{buildroot}%{_sysconfdir}/xsigner/keys
install -D -m 0640 deploy/config/xsigner.yaml %{buildroot}%{_sysconfdir}/xsigner/xsigner.yaml
for d in xproxy xgate xrelay xot; do
  install -d -m 0750 %{buildroot}%{_localstatedir}/log/$d
  install -d -m 0700 %{buildroot}%{_sharedstatedir}/$d
done

# Documentation, manual pages, configuration schema and shell completion.
install -d -m 0755 %{buildroot}%{_docdir}/%{name}
install -m 0644 README.md docs/*.md %{buildroot}%{_docdir}/%{name}/
install -D -m 0644 docs/man/xproxy.8      %{buildroot}%{_mandir}/man8/xproxy.8
install -D -m 0644 docs/man/xgate.8      %{buildroot}%{_mandir}/man8/xgate.8
install -D -m 0644 docs/man/xrelay.8     %{buildroot}%{_mandir}/man8/xrelay.8
install -D -m 0644 docs/man/xot.8        %{buildroot}%{_mandir}/man8/xot.8
install -D -m 0644 docs/man/xproxyctl.8   %{buildroot}%{_mandir}/man8/xproxyctl.8
install -D -m 0644 docs/man/xproxy-replay.8 %{buildroot}%{_mandir}/man8/xproxy-replay.8
install -D -m 0644 docs/man/xproxy-simulate.8 %{buildroot}%{_mandir}/man8/xproxy-simulate.8
install -D -m 0644 docs/man/xproxy-fleet.8 %{buildroot}%{_mandir}/man8/xproxy-fleet.8
install -D -m 0644 docs/man/xsigner.8     %{buildroot}%{_mandir}/man8/xsigner.8
install -D -m 0644 docs/man/xproxy.yaml.5 %{buildroot}%{_mandir}/man5/xproxy.yaml.5
install -D -m 0644 internal/config/schema/xproxy.schema.json %{buildroot}%{_datadir}/xproxy/xproxy.schema.json
install -D -m 0644 deploy/grafana/xproxy-overview.json %{buildroot}%{_datadir}/xproxy/grafana/xproxy-overview.json
install -D -m 0644 deploy/grafana/xproxy-security.json %{buildroot}%{_datadir}/xproxy/grafana/xproxy-security.json
install -D -m 0644 deploy/grafana/README.md %{buildroot}%{_datadir}/xproxy/grafana/README.md
install -D -m 0644 deploy/prometheus/xproxy-alerts.yaml %{buildroot}%{_datadir}/xproxy/prometheus/xproxy-alerts.yaml

# The behaviour packs: signed, versioned detection data the OT daemon reads at
# start. They ship as sources, unsigned, because a private key in a package is
# not a private key -- the estate signs the directory it installs, with
# `xproxyctl packs sign`, and lists the public half in `packs.keys`. The
# directory is 0755 and the files 0644 so that a daemon running as xot can read
# them and only root can change them.
install -d -m 0755 %{buildroot}%{_datadir}/xproxy/packs
install -m 0644 packs/*.yaml %{buildroot}%{_datadir}/xproxy/packs/
install -m 0644 packs/README.md %{buildroot}%{_datadir}/xproxy/packs/README.md
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

%post xgate
%systemd_post xgate.service xgate.socket

%preun xgate
%systemd_preun xgate.service xgate.socket

%postun xgate
%systemd_postun_with_restart xgate.service

%post signer
%systemd_post xsigner.service

%preun signer
%systemd_preun xsigner.service

%postun signer
%systemd_postun_with_restart xsigner.service

%post xrelay
%systemd_post xrelay.service xrelay.socket

%post xot
%systemd_post xot.service xot.socket

%preun xrelay
%systemd_preun xrelay.service xrelay.socket

%preun xot
%systemd_preun xot.service xot.socket

%postun xrelay
%systemd_postun_with_restart xrelay.service

%postun xot
%systemd_postun_with_restart xot.service

%post admin
%systemd_post xproxy-admin.service

%preun admin
%systemd_preun xproxy-admin.service

%postun admin
%systemd_postun_with_restart xproxy-admin.service

%post fleet
%systemd_post xproxy-fleet.service

%preun fleet
%systemd_preun xproxy-fleet.service

%postun fleet
%systemd_postun_with_restart xproxy-fleet.service

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
%{_bindir}/xproxy-replay
%{_bindir}/xproxy-simulate
%{_mandir}/man8/xproxy.8*
%{_mandir}/man8/xproxyctl.8*
%{_mandir}/man8/xproxy-replay.8*
%{_mandir}/man8/xproxy-simulate.8*
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
%{_tmpfilesdir}/xproxy-config.conf
%{_tmpfilesdir}/xproxy-cluster.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/xproxy
%dir %attr(0750,root,xproxy-config) %{_sysconfdir}/xproxy
%config(noreplace) %attr(0640,root,xproxy-config) %{_sysconfdir}/xproxy/xproxy.yaml
%dir %attr(0750,xproxy,xproxy) %{_localstatedir}/log/xproxy
%dir %attr(0700,xproxy,xproxy) %{_sharedstatedir}/xproxy

%files xgate
%{_bindir}/xgate
%{_mandir}/man8/xgate.8*
%{_unitdir}/xgate.service
%{_unitdir}/xgate.socket
%config(noreplace) %{_sysconfdir}/logrotate.d/xgate
%config(noreplace) %attr(0640,root,xproxy-config) %{_sysconfdir}/xproxy/xgate.yaml
%dir %attr(0750,xgate,xgate) %{_localstatedir}/log/xgate
%dir %attr(0700,xgate,xgate) %{_sharedstatedir}/xgate

%files xrelay
%{_bindir}/xrelay
%{_mandir}/man8/xrelay.8*
%{_unitdir}/xrelay.service
%{_unitdir}/xrelay.socket
%config(noreplace) %{_sysconfdir}/logrotate.d/xrelay
%config(noreplace) %attr(0640,root,xproxy-config) %{_sysconfdir}/xproxy/xrelay.yaml
%dir %attr(0750,xrelay,xrelay) %{_localstatedir}/log/xrelay
%dir %attr(0700,xrelay,xrelay) %{_sharedstatedir}/xrelay

%files xot
%{_bindir}/xot
%dir %{_datadir}/xproxy/packs
%{_datadir}/xproxy/packs/*.yaml
%{_datadir}/xproxy/packs/README.md
%{_mandir}/man8/xot.8*
%{_unitdir}/xot.service
%{_unitdir}/xot.socket
%config(noreplace) %{_sysconfdir}/logrotate.d/xot
%config(noreplace) %attr(0640,root,xproxy-config) %{_sysconfdir}/xproxy/xot.yaml
%dir %attr(0750,xot,xot) %{_localstatedir}/log/xot
%dir %attr(0700,xot,xot) %{_sharedstatedir}/xot

%files signer
%{_bindir}/xsigner
%{_mandir}/man8/xsigner.8*
%{_unitdir}/xsigner.service
%{_tmpfilesdir}/xsigner.conf
# 0750 root:xsigner so the helper can read it and nothing else can look, and
# the keys directory 0700 xsigner so only the helper can list it at all.
%dir %attr(0750,root,xsigner) %{_sysconfdir}/xsigner
%dir %attr(0700,xsigner,xsigner) %{_sysconfdir}/xsigner/keys
%config(noreplace) %attr(0640,root,xsigner) %{_sysconfdir}/xsigner/xsigner.yaml

%files admin
%{_bindir}/xproxy-admin
%{_unitdir}/xproxy-admin.service

%files fleet
%{_bindir}/xproxy-fleet
%{_unitdir}/xproxy-fleet.service
%{_mandir}/man8/xproxy-fleet.8*
%dir %attr(0750,xproxy-fleet,xproxy-fleet) %{_sharedstatedir}/xproxy-fleet
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
