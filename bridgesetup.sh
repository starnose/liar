#!/bin/bash
#
# Simple, dumb script to tear down and set up a network bridge between eth0
# and eth1 on a dhcp-enabled network.
#
# Requires brctl, if you're on debian that's part of bridge-utils
#

# Bridges and NetworkManager don't seem to get on
pkill NetworkManager

# Blank out net addresses and take down all involved interfaces
ifconfig eth0 0.0.0.0
ifconfig eth1 0.0.0.0
ifconfig eth0 down
ifconfig eth1 down
ifconfig mybr down

# Destroy any previous bridge instance
brctl delbr mybr

# set up ipv4 forwarding
sysctl net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.eth0.proxy_arp=1
sysctl -w net.ipv4.conf.all.proxy_arp=1

# create a new bridge
brctl addbr mybr
brctl addif mybr eth0
brctl addif mybr eth1

# bring up the interfaces again
ifconfig eth0 up
ifconfig eth1 up
ifconfig mybr up

# grab an IP address for the new bridged interface
dhclient mybr
