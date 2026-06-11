import time
from scapy.all import RadioTap, Dot11, Dot11Auth, AsyncSniffer
from core.enums import HandshakeFuzzMode
from fuzzers.BaseFuzzer import BaseFuzzer
from core.frames import get_random_client_mac, get_handshake_attack_params

class HandshakeFuzz(BaseFuzzer):
    """
    Handles multi-step attacks like the Authentication/Association handshake.
    Now uses asynchronous sniffing to avoid blocking the main loop.
    """
    def __init__(self, target_mac, interface, attack_mode: HandshakeFuzzMode, ssid, client_mac=None):
        self.temp_client_mac = client_mac or get_random_client_mac()
        self._fixed_client_mac = client_mac is not None
        if attack_mode not in HandshakeFuzzMode:
            raise ValueError(f"Invalid attack mode: {attack_mode!r}.")
        
        super().__init__(target_mac, self.temp_client_mac, interface)
        
        self.attack_mode = attack_mode
        self.ssid = ssid
        self.state = "NEED_AUTH"
        self.auth_sent_time = 0
        
        # Start background sniffer
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            filter=f"wlan addr2 {self.target_mac}",
            prn=self._auth_handler,
            store=0
        )
        self.sniffer.start()

    def _auth_handler(self, pkt):
        # Look for Auth responses to our MAC
        if pkt.haslayer(Dot11Auth) and pkt.addr1 == self.temp_client_mac:
            if pkt[Dot11Auth].status == 0:
                print(f"[+] Authentication Successful for {self.temp_client_mac}. Triggering Assoc Req...")
                self.state = "AUTH_SUCCESS"

    def setup(self):
        # No blocking setup needed
        pass

    def next_frame(self):
        if self.state == "NEED_AUTH":
            auth_pkt = RadioTap() / Dot11(addr1=self.target_mac, addr2=self.temp_client_mac, addr3=self.target_mac) / \
                       Dot11Auth(algo=0, seqnum=1, status=0)
            self.state = "WAIT_AUTH"
            self.auth_sent_time = time.time()
            return auth_pkt
            
        elif self.state == "WAIT_AUTH":
            # If waited more than 1s without success, try again
            if time.time() - self.auth_sent_time > 1.0:
                self.state = "NEED_AUTH"
            return None # Skip this tick in wifuzzer.py
            
        elif self.state == "AUTH_SUCCESS":
            # We are authenticated! Send fuzzed Assoc Req
            type, subtype, payload = get_handshake_attack_params(self.attack_mode)
            dot11 = Dot11(type=type, subtype=subtype, addr1=self.target_mac, addr2=self.temp_client_mac, addr3=self.target_mac)
            packet = RadioTap() / dot11 / payload(self.ssid)
            
            # Reset for next fuzzing attempt
            self.state = "NEED_AUTH"
            if not self._fixed_client_mac:
                self.temp_client_mac = get_random_client_mac()
                
            return packet

    def is_exhausted(self):
        return False

    def __del__(self):
        if hasattr(self, 'sniffer') and self.sniffer.running:
            self.sniffer.stop()