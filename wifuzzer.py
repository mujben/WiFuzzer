#!/usr/bin/env python3
import os
import re
import sys
import time
import argparse
from collections import deque
from scapy.all import Dot11, Dot11Deauth, sendp

from core.DeviceHealthMonitor import DeviceHealthMonitor
from core.enums import HandshakeFuzzMode, StatelessFuzzMode, StatefulFuzzMode
from fuzzers.SeqFuzz import SeqFuzz
from fuzzers.StatefulFuzz import StatefulFuzz
from fuzzers.StatelessFuzz import StatelessFuzz
from fuzzers.HandshakeFuzz import HandshakeFuzz

def get_available_modes():
    """Returns a list of available fuzzing modes."""
    stateless = [m.name for m in StatelessFuzzMode]
    stateful = [m.name for m in StatefulFuzzMode]
    handshake = [m.name for m in HandshakeFuzzMode]
    special = ["seq_fuzz"]
    return stateless + stateful + handshake + special

def validate_mac(macs):
    """Validate one MAC address or an iterable of MAC addresses."""
    if macs is None:
        return
    if isinstance(macs, str):
        macs = [macs]
    for mac in macs:
        if mac is None:
            continue
        if not re.match(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$', mac):
            raise ValueError(f"Invalid MAC address format: {mac}")

def main():
    parser = argparse.ArgumentParser(description="Wi-Fi Fuzzer tool.", epilog="Example usage: python fuzzer.py -t 02:00:00:00:00:00 -i wlan0")
    parser.add_argument("-t", "--target-mac", help="MAC address of the targeted device")
    parser.add_argument("-c", "--client-mac", help="MAC address of the client device")
    parser.add_argument("-T", "--target-type", choices=["AP", "STA"], default="AP", help="Type of the target device: 'AP' for Access Point, 'STA' for Station (default: AP)")
    parser.add_argument("-i", "--iface", default="wlan0", help="Wireless interface to use set to monitor mode (default: wlan0)")
    parser.add_argument("-m", "--mode", choices=get_available_modes(), default="ssid_len", help="Fuzzing mode to use (default: ssid_len)")
    parser.add_argument("-s", "--ssid", help="SSID of the target network")
    parser.add_argument("-I", "--intensity", type=float, default=0.05, help="IFS (Inter-frame spacing) in seconds (default: 0.05)")
    parser.add_argument("--log-csv", action="store_true", help="Enable CSV logging of device health data")

    if len(sys.argv) == 1:
        parser.print_help()
        exit(0)

    args = parser.parse_args()

    # Configuration of the attack
    IFS = args.intensity
    MONITOR_TIMEOUT = 2 if args.target_type == "AP" else 10

    target_mac = args.target_mac
    client_mac = args.client_mac
    if not (target_mac or client_mac):
        raise ValueError("Error: You must specify either an AP MAC address or a client MAC address.")
    validate_mac([target_mac, client_mac])

    if not os.path.exists(f"/sys/class/net/{args.iface}"):
        raise ValueError(f"Error: Interface {args.iface} does not exist.")

    print(f"[*] {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}")
    print(f"[*] Starting fuzzing device {target_mac} on interface {args.iface}")
    print("[!] Press Ctrl+C to stop.")

    # Initialize the device health monitor
    monitor = DeviceHealthMonitor(target_mac, args.iface, target_type=args.target_type, log_csv=args.log_csv)
    monitor.start()

    # Queue for storing sent frames to identify successful hit
    history = deque(maxlen=int(1/IFS * MONITOR_TIMEOUT * 2))
    time_of_death = 0
    count = 0

    # Fuzzer initialization
    if args.mode == "seq_fuzz":
        fuzzer = SeqFuzz(target_mac=target_mac, interface=args.iface)
    elif args.mode in HandshakeFuzzMode.__members__:
        fuzzer = HandshakeFuzz(target_mac=target_mac, interface=args.iface, attack_mode=HandshakeFuzzMode[args.mode], ssid=args.ssid)
    elif args.mode in StatefulFuzzMode.__members__:
        fuzzer = StatefulFuzz(target_mac=target_mac, interface=args.iface, attack_mode=StatefulFuzzMode[args.mode], ssid=args.ssid)
    else:
        fuzzer = StatelessFuzz(target_mac=target_mac, interface=args.iface, target_type=args.target_type, attack_mode=StatelessFuzzMode[args.mode])

    try:
        fuzzer.setup()
        while True:
            if not monitor.is_target_alive(timeout=MONITOR_TIMEOUT):
                if args.target_type == "AP":
                    print(f"[!] Target {target_mac} is not responding.")
                    print(f"[*] Crash detected after {count} fuzzed frames.")
                if not monitor.active_probe():
                    time_of_death = monitor.last_seen
                    print("[*] Active probe failed, confirming target is unresponsive. Stopping fuzzing.")
                    break
                else:
                    monitor.reset_last_seen()  # Reset last seen to avoid false positives
            
            frame = fuzzer.next_frame()
            if frame is None:
                if fuzzer.is_exhausted():
                    print("[*] Fuzzer has exhausted all frames. Stopping fuzzing.")
                    break
                time.sleep(IFS)
                continue
                
            sendp(frame, iface=args.iface, verbose=False)
            history.append((frame, time.time()))
            count += 1
            time.sleep(IFS)
            if count % 100 == 0:
                print(f"[*] Sent {count} frames so far...")

    except KeyboardInterrupt:
        print("\n[*] Fuzzing stopped by user.")
    except OSError as e:
        print(f"\n[!] OS error occurred: {e}")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
    finally:
        if time_of_death != 0:
            for frame, timestamp in history:
                if frame is None: continue
                if timestamp >= time_of_death - 0.5 and timestamp <= time_of_death + 0.5:
                    print(f"Potential crash-inducing frame sent at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}:")
                    print(f"{frame.summary()}\n"
                            f"ID: {getattr(frame.getlayer(Dot11), 'ID', 'N/A')} |"
                            f"Seq: {frame[Dot11].SC >> 4 if Dot11 in frame else 'N/A'} |"
                            f"Reason: {getattr(frame.getlayer(Dot11Deauth), 'reason', 'N/A')} |"
                            f"Len: {len(frame)}")
        monitor.stop()

if __name__ == "__main__":
    main()