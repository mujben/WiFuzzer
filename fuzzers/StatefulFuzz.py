import time
from scapy.all import RadioTap, Dot11, Dot11Elt, Dot11Auth, Dot11AssoReq, Dot11AssoResp, AsyncSniffer, sendp
from fuzzers.BaseFuzzer import BaseFuzzer
from core.enums import StatefulFuzzMode
from core.frames import get_random_client_mac, get_stateful_attack_params


class StatefulFuzz(BaseFuzzer):
    def __init__(self, target_mac, interface, attack_mode: StatefulFuzzMode, ssid, client_mac=None):
        self.client_mac = client_mac or get_random_client_mac()
        if attack_mode not in StatefulFuzzMode:
            raise ValueError(f"Invalid attack mode: {attack_mode!r}.")
        
        super().__init__(target_mac, self.client_mac, interface)

        self.attack_mode = attack_mode
        self.ssid = ssid
        self.state = "NEED_AUTH"
        self.last_keepalive_time = time.time()

        self.sniffer = AsyncSniffer(
            iface=self.interface,
            filter=f"wlan addr2 {self.target_mac}",
            prn=self._pkt_handler,
            store=0
        )

    def _pkt_handler(self, pkt):
        if pkt.addr1 != self.client_mac:
            return

        # Look for Auth responses to our MAC
        if pkt.haslayer(Dot11Auth) and pkt.addr1 == self.client_mac:
            if pkt.getlayer(Dot11Auth).status == 0:
                print(f"[+] Authentication Successful for {self.client_mac}. Triggering Assoc Req...")
                self.state = "AUTH_SUCCESS"

        # Look for Assoc responses to our MAC
        if pkt.haslayer(Dot11AssoResp) and pkt.addr1 == self.client_mac:
            if pkt.getlayer(Dot11AssoResp).status == 0:
                print(f"[+] Association Successful for {self.client_mac}. Starting fuzzing...")
                self.state = "ASSOC_SUCCESS"
                
    def setup(self):
        """
        Perform 4 way handshake to establish a connection
        """
        self.sniffer.start()
        auth_sent_time = 0
        assoc_sent_time = 0
        while self.state != "ASSOC_SUCCESS":
            if self.state == "NEED_AUTH":
                dot11 = Dot11(type=0, subtype=11, addr1=self.target_mac, addr2=self.client_mac, addr3=self.target_mac) 
                auth = Dot11Auth(algo=0, seqnum=1, status=0)
                auth_pkt = RadioTap() / dot11 / auth
                sendp(auth_pkt, iface=self.interface, verbose=0)

                self.state = "WAIT_AUTH"
                auth_sent_time = time.time()
            
            elif self.state == "WAIT_AUTH":
                if time.time() - auth_sent_time > 2:
                    print("[-] Authentication timed out. Retrying...")
                    self.client_mac = get_random_client_mac()
                    self.state = "NEED_AUTH"
            
            elif self.state == "AUTH_SUCCESS":
                dot11 = Dot11(type=0, subtype=0, addr1=self.target_mac, addr2=self.client_mac, addr3=self.target_mac)
                asso_req = Dot11AssoReq(cap=0x1100, listen_interval=0x00a)
                ssid_tag = Dot11Elt(ID=0, len=len(self.ssid), info=self.ssid)
                rates_tag = Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")

                asso_pkt = RadioTap() / dot11 / asso_req / ssid_tag / rates_tag
                sendp(asso_pkt, iface=self.interface, verbose=0)

                self.state = "WAIT_ASSOC"
                assoc_sent_time = time.time()

            elif self.state == "WAIT_ASSOC":
                if time.time() - assoc_sent_time > 2:
                    print("[-] Association timed out. Retrying...")
                    self.client_mac = get_random_client_mac()
                    self.state = "NEED_AUTH"
            
            time.sleep(0.1)
        self.sniffer.stop()
    
    def next_frame(self):
        if time.time() - self.last_keepalive_time > 7.5:
            # Send keepalive frames to maintain connection
            self.last_keepalive_time = time.time()
            return RadioTap() / Dot11(type=2, subtype=4, addr1=self.target_mac, addr2=self.client_mac, addr3=self.target_mac)
        type, subtype, payload = get_stateful_attack_params(self.attack_mode)
        dot11 = Dot11(type=type, subtype=subtype, addr1=self.target_mac, addr2=self.client_mac, addr3=self.target_mac)
        
        return RadioTap() / dot11 / payload()

    def is_exhausted(self):
        return False

    def __del__(self):
        if hasattr(self, 'sniffer') and self.sniffer.running:
            self.sniffer.stop()