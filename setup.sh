#!/bin/bash
set -x
modprobe -r mac80211_hwsim
modprobe mac80211_hwsim radios=2
ifconfig wlan0 down
iw dev wlan0 set type monitor
ifconfig wlan0 up
iw dev wlan0 set channel 6
