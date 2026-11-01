#!/bin/sh
# End-to-end test of the systemd unit against the mock device. Runs as root on
# a host whose PID 1 is systemd (the CI runner, or a systemd container):
#   sudo packaging/test-systemd.sh <dir with openskey and mock-device>
# Installs the unit, the sysusers entry and an environment file, starts the
# service, and checks it registers, runs as its own user, dispatches a button
# press to its command, and comes back after it is killed.
set -eu
bin="${1:?usage: test-systemd.sh <dir with openskey and mock-device>}"
here="$(cd "$(dirname "$0")" && pwd)"

install -m 0755 "$bin/openskey" /usr/bin/openskey
install -m 0644 "$here/openskey.service" /etc/systemd/system/openskey.service
install -D -m 0644 "$here/openskey.sysusers" /usr/lib/sysusers.d/openskey.conf
systemd-sysusers openskey.conf
id openskey

install -d /etc/openskey
# The example file must be a valid EnvironmentFile; the test values follow it.
cp "$here/openskey.env" /etc/openskey/openskey.env
cat >> /etc/openskey/openskey.env <<'ENV'
IPADDRESS=127.0.0.1
SKEY_DEVICE_PORT=1161
HOST_IPADDRESS=127.0.0.1
NAME=systemd-test
KEEPALIVE_INTERVAL=3
SKEY_FILE='echo "DISPATCHED device=$1 name=$2 func=$SKEY_FUNC p1=$SKEY_P1"'
ENV
systemd-analyze verify /etc/systemd/system/openskey.service

"$bin/mock-device" --port 1161 >/tmp/mock.log 2>&1 &
mock=$!
trap 'kill $mock 2>/dev/null || true; systemctl stop openskey 2>/dev/null || true' EXIT
sleep 1

systemctl daemon-reload
systemctl start openskey

wait_for() { # <pattern> <seconds>
  i=0
  while [ "$i" -lt "$2" ]; do
    if journalctl -u openskey --no-pager -o cat | grep -q "$1"; then return 0; fi
    sleep 1; i=$((i + 1))
  done
  echo "FAILED: no \"$1\" in the journal after $2 s" >&2
  journalctl -u openskey --no-pager -o cat >&2
  exit 1
}

wait_for 'registration verified' 15
user="$(ps -o user= -p "$(systemctl show -p MainPID --value openskey)")"
[ "$user" = openskey ] || { echo "FAILED: runs as $user, not openskey" >&2; exit 1; }
echo "ok: registered and verified, running as $user"

"$bin/mock-device" --button FILE --host 127.0.0.1:54925 --params 3,0,0,0
wait_for 'DISPATCHED device=.* name=systemd-test func=FILE p1=3' 15
echo "ok: the button press ran the configured command"

systemctl kill -s KILL openskey
sleep 7
systemctl is-active --quiet openskey || { echo "FAILED: not restarted" >&2; exit 1; }
echo "ok: restarted after being killed"
echo "systemd unit test passed"
