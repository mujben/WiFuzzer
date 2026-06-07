import time
from scapy.all import RadioTap, Dot11, Dot11Auth, srp1
from fuzzers.BaseFuzzer import BaseFuzzer
from core.frames import get_random_client_mac, _get_fuzzed_assoc_req

class StatefulFuzz(BaseFuzzer):
    """
    Handles multi-step attacks like the Authentication/Association handshake.
    """
    def __init__(self, target_mac, interface):
        # Generates one stable client MAC for the duration of one handshake attempt
        self.temp_client_mac = get_random_client_mac()
        super().__init__(target_mac, self.temp_client_mac, interface)
        self.authenticated = False

    def setup(self):
        """Step 1: Send a valid Authentication Request and wait for Response."""
        print(f"Attempting Auth with {self.temp_client_mac}")
        
        auth_pkt = RadioTap() / Dot11(addr1=self.target_mac, addr2=self.temp_client_mac, addr3=self.target_mac) / \
                   Dot11Auth(algo=0, seqnum=1, status=0)
        
        # Send and wait for 1 response packet
        ans = srp1(auth_pkt, iface=self.interface, timeout=1, verbose=False)
        
        if ans and ans.haslayer(Dot11Auth) and ans[Dot11Auth].status == 0:
            print("Authentication Successful. State: Authenticated.")
            self.authenticated = True
        else:
            print("Authentication Failed or Timed Out.")
            self.authenticated = False

        return auth_pkt

    def next_frame(self):
        """Step 2: If authenticated, send the fuzzed Association Request."""
        if not self.authenticated:
            return self.setup() # Try to authenticate again and return the Auth frame
        
        # Create fuzzed Association Request
        dot11 = Dot11(addr1=self.target_mac, addr2=self.temp_client_mac, addr3=self.target_mac)
        packet = RadioTap() / dot11 / _get_fuzzed_assoc_req()
        
        # After sending Assoc, we reset for the next attempt with a new MAC
        self.authenticated = False
        self.temp_client_mac = get_random_client_mac()
        
        return packet