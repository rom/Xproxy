#!/bin/sh
# Install xproxy on macOS: users, directories, binaries, launchd jobs, the
# seatbelt profile, pf anchor and newsyslog rotation. Run as root from a
# checkout after `make build-darwin`, or from an unpacked release tarball:
#
#   sudo sh deploy/macos/install.sh bin/darwin-arm64
#
# Idempotent: existing users, configuration and users file are kept.
set -eu

BIN=${1:-.}
PREFIX=${PREFIX:-/usr/local}
ETC=$PREFIX/etc/xproxy
LOG=$PREFIX/var/log/xproxy
RUN=$PREFIX/var/run/xproxy
STATE=$PREFIX/var/lib/xproxy
HERE=$(cd "$(dirname "$0")" && pwd)

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
[ "$(uname -s)" = Darwin ] || { echo "this installer is for macOS"; exit 1; }
for b in xproxy xproxyctl xproxy-admin; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b (run make build-darwin)"; exit 1; }
done

# System users and group with ids below 500 (hidden from the login window).
free_id() {
  key=$1; db=$2; id=400
  while dscl . -list "$db" "$key" | awk '{print $2}' | grep -qx "$id"; do id=$((id + 1)); done
  echo "$id"
}
ensure_group() {
  g=$1
  dscl . -read "/Groups/$g" >/dev/null 2>&1 && return
  gid=$(free_id PrimaryGroupID /Groups)
  dscl . -create "/Groups/$g"
  dscl . -create "/Groups/$g" PrimaryGroupID "$gid"
  dscl . -create "/Groups/$g" RealName "$2"
  echo "created group $g ($gid)"
}
ensure_user() {
  u=$1; g=$2
  dscl . -read "/Users/$u" >/dev/null 2>&1 && return
  uid=$(free_id UniqueID /Users)
  gid=$(dscl . -read "/Groups/$g" PrimaryGroupID | awk '{print $2}')
  dscl . -create "/Users/$u"
  dscl . -create "/Users/$u" UniqueID "$uid"
  dscl . -create "/Users/$u" PrimaryGroupID "$gid"
  dscl . -create "/Users/$u" UserShell /usr/bin/false
  dscl . -create "/Users/$u" NFSHomeDirectory /var/empty
  dscl . -create "/Users/$u" RealName "$3"
  dscl . -create "/Users/$u" IsHidden 1
  echo "created user $u ($uid)"
}
ensure_group _xproxy "xproxy reverse proxy"
ensure_user _xproxy _xproxy "xproxy reverse proxy"
ensure_user _xproxy-admin _xproxy "xproxy web GUI"
dseditgroup -o edit -a _xproxy-admin -t user _xproxy 2>/dev/null || true

# Binaries, manual pages, configuration schema and shell completion.
install -d -m 0755 "$PREFIX/bin"
for b in xproxy xproxyctl xproxy-admin; do install -m 0755 "$BIN/$b" "$PREFIX/bin/$b"; done
if [ -d "$HERE/../../docs/man" ]; then
  install -d -m 0755 "$PREFIX/share/man/man8" "$PREFIX/share/man/man5" "$PREFIX/share/xproxy"
  install -m 0644 "$HERE/../../docs/man/xproxy.8" "$HERE/../../docs/man/xproxyctl.8" "$PREFIX/share/man/man8/"
  install -m 0644 "$HERE/../../docs/man/xproxy.yaml.5" "$PREFIX/share/man/man5/"
  install -m 0644 "$HERE/../../internal/config/schema/xproxy.schema.json" "$PREFIX/share/xproxy/"
fi
install -d -m 0755 "$PREFIX/share/zsh/site-functions" "$PREFIX/share/bash-completion/completions" "$PREFIX/share/fish/vendor_completions.d"
"$PREFIX/bin/xproxyctl" completion zsh > "$PREFIX/share/zsh/site-functions/_xproxyctl"
"$PREFIX/bin/xproxyctl" completion bash > "$PREFIX/share/bash-completion/completions/xproxyctl"
"$PREFIX/bin/xproxyctl" completion fish > "$PREFIX/share/fish/vendor_completions.d/xproxyctl.fish"

# Directories: configuration readable by the group, everything the daemon
# writes owned by it; state is private.
install -d -m 0750 -o root -g _xproxy "$ETC"
install -d -m 0750 -o _xproxy -g _xproxy "$LOG"
install -d -m 0750 -o _xproxy -g _xproxy "$RUN"
install -d -m 0700 -o _xproxy -g _xproxy "$STATE"
if [ ! -f "$ETC/xproxy.yaml" ]; then
  sed -e "s|/etc/xproxy|$ETC|g" -e "s|/var/log/xproxy|$LOG|g" -e "s|/run/xproxy|$RUN|g" -e "s|/var/lib/xproxy|$STATE|g" \
    "$HERE/../config/xproxy.yaml" > "$ETC/xproxy.yaml"
  chown _xproxy-admin:_xproxy "$ETC/xproxy.yaml"; chmod 0640 "$ETC/xproxy.yaml"
  echo "installed $ETC/xproxy.yaml (edit before starting)"
fi
install -m 0644 -o root -g _xproxy "$HERE/xproxy.sb" "$ETC/xproxy.sb"
install -m 0644 -o root -g wheel "$HERE/pf-xproxy.conf" "$ETC/pf-xproxy.conf"
install -m 0644 -o root -g wheel "$HERE/newsyslog-xproxy.conf" /etc/newsyslog.d/xproxy.conf
[ -f "$ETC/admin-users" ] || { : > "$ETC/admin-users"; chown _xproxy-admin:_xproxy "$ETC/admin-users"; chmod 0640 "$ETC/admin-users"; }

# The GUI's restart action: launchctl through sudo, nothing else.
cat > /etc/sudoers.d/xproxy-admin <<SUDO
_xproxy-admin ALL=(root) NOPASSWD: /bin/launchctl kickstart -k system/com.sysctl.xproxy
SUDO
chmod 0440 /etc/sudoers.d/xproxy-admin

# launchd jobs.
for j in com.sysctl.xproxy com.sysctl.xproxy-admin; do
  install -m 0644 -o root -g wheel "$HERE/$j.plist" "/Library/LaunchDaemons/$j.plist"
done
"$PREFIX/bin/xproxy" -config "$ETC/xproxy.yaml" -validate || {
  echo "configuration invalid; fix $ETC/xproxy.yaml then: sudo launchctl bootstrap system /Library/LaunchDaemons/com.sysctl.xproxy.plist"
  exit 0
}
launchctl bootout system/com.sysctl.xproxy 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.sysctl.xproxy.plist
echo "xproxy started: sudo $PREFIX/bin/xproxyctl -socket $RUN/mgmt.sock status"
echo "web GUI: $PREFIX/bin/xproxy-admin -users $ETC/admin-users user add admin -role operator"
echo "         sudo launchctl bootstrap system /Library/LaunchDaemons/com.sysctl.xproxy-admin.plist"
echo "firewall: see docs/HARDENING_MACOS.md for the pf anchor"
