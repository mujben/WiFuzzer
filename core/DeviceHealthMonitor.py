import time
import csv
from scapy.all import sniff, srp1, RadioTap, Dot11, Dot11Elt, Dot11ProbeReq
from threading import Thread, Lock

class DeviceHealthMonitor:
    def __init__(self, target_mac, iface, target_type="AP", log_csv=True):
        self.target_mac = target_mac.lower()
        self.iface = iface
        self.target_type = target_type
        self.last_seen_lock = Lock()
        self.last_seen = time.time()
        self.is_running = True

        self.log_csv = log_csv
        if self.log_csv:
            self.log_file = f"device_health_log_{time.strftime('%Y%m%d-%H%M%S')}.csv"
            self._init_csv()
            
    def _init_csv(self):
        with open(self.log_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Seconds_Since_Last_Beacon", "Probe_Response_Success"])

    def _packet_handler(self, packet):
        if not packet.haslayer(Dot11):
            return
        if packet.addr2 and packet.addr2.lower() == self.target_mac:
            with self.last_seen_lock:
                self.last_seen = time.time()

    def _sniff_loop(self):
        while self.is_running:
            bpf_filter = f"wlan addr2 {self.target_mac}"
            sniff(iface=self.iface, filter=bpf_filter, prn=self._packet_handler, store=0, timeout=1, stop_filter=lambda x: not self.is_running)

    def start(self):
        self.sniffer_thread = Thread(target=self._sniff_loop, daemon=True)
        self.sniffer_thread.start()

    def is_target_alive(self, timeout=10):
        """Check if the target is still alive based on the timeout. Returns True if alive, False if not."""
        now = time.time()
        delta = now - self.last_seen
        alive = delta < timeout

        if self.log_csv:
            with open(self.log_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([now, round(delta, 2), "OK" if alive else "FAIL"])
        return alive

    def reset_last_seen(self):
        """Reset the last seen timestamp to the current time."""
        with self.last_seen_lock:
            self.last_seen = time.time()

    def stop(self):
        """Stop the device health monitor."""
        self.is_running = False
        if hasattr(self, 'sniffer_thread'):
            self.sniffer_thread.join()

    def active_probe(self):
        """
        Sends probe requests to the target AP and checks for response.
        """
        if self.target_type != "AP": return True

        probe = RadioTap() / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2="02:00:00:21:37:69", addr3=self.target_mac) / Dot11ProbeReq() / Dot11Elt(ID=0, info="")
        ans = srp1(probe, iface=self.iface, timeout=0.5, verbose=False)

        if ans:
            with self.last_seen_lock:
                self.last_seen = time.time()
                return True
        return False
