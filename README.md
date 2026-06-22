# WiFuzzer
A program intended for fuzz testing the 802.11 protocols. It can perform tests with use of mac80211_hwsim or over the air (with limited capabilities).
WiFuzzer is a Python program, which uses the Scapy library for convenience when operating on Wi-Fi frames.

*Disclaimer: perform tests only on the networks that you own or have full rights to test.*

## Description
WiFuzzer has five main modules:
- **StatelessFuzz:**   state 1 (unauthenticated, unassociated), basic fuzzing with the use of mainly management frames.
- **SeqFuzz:**         state 1 (unauthenticated, unassociated), testing how an access point manages unnatural sequential numbers of frames in the context of a whole transmission.
- **HandshakeFuzz:**    state 2 (authenticated, unassociated), sending malicious Association Request frames to test the AP's state machine.
- **StatefulFuzz:**     state 3 (authenticated, associated), performing tests with mainly Action frames in the context of an established session with the AP.
- **DeviceHealthMonitor:** a module designed for monitoring the target's responsiveness during the other modules' execution. It uses passive and active techniques.

## Requirements
- Python 3.x
- Scapy
- Root privileges (required to set the interface into monitor mode and to send raw frames)

```
pip install -r requirements.txt
```

## How to run
There are two options to run the program: using mac80211_hwsim and over the air.
```
git clone https://github.com/mujben/WiFuzzer.git
cd WiFuzzer
```
**mac80211_hwsim**:
Run the setup script and make the simple configuration of hostapd.
```
chmod +x setup.sh
./setup.sh
```
Sometimes it is needed to switch the interface into monitor mode manually.

Example contents of */etc/hostapd/hostapd.conf*:
```
# /etc/hostapd/hostapd.conf
interface=wlan1
driver=nl80211
ssid=WiFuzzer
hw_mode=g
channel=6
wmm_enabled=1
# open auth system
auth_algs=1
```
Run hostapd:
```
hostapd [-dd] /etc/hostapd/hostapd.conf
```

**Over the air**:
Set the wireless interface into monitor mode using the commands from *setup.sh*.
Start the fuzzer on the target that you have permissions to test.

> **Note:** the over-the-air mode has limited reliability, since Scapy cannot send ACK frames within the required SIFS window. This can cause the AP to drop the connection during longer test sequences (e.g. HandshakeFuzz, StatefulFuzz).

## Example usage
In order to see all options of the program type
```
./wifuzzer.py -h
```
To perform tests on the AP type
```
./wifuzzer.py -i [interface in monitor mode] -t [AP's MAC address] -s [AP's SSID - only for stateful and handshake fuzzing] -m [attack mode]
```
First three available attack modes (`-m`): `ssid_len`, `ssid_duplication`, `random_id`.

The `-s` (SSID) option is required for HandshakeFuzz and StatefulFuzz, since both need a valid SSID to build the Probe/Association Request frames used to reach an authenticated/associated state with the AP.
