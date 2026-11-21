#!/bin/sh

interface=${1:?missing WireGuard interface}
trap 'exit 0' INT TERM

while :; do
    /usr/local/sbin/vpp-wg-syncconf "$interface"
    sleep 30 &
    wait $!
done
