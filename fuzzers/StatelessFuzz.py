from scapy.all import RadioTap, Dot11

from core.frames import get_random_client_mac, get_stateless_attack_params, get_base
from core.enums import StatelessFuzzMode
from fuzzers.BaseFuzzer import BaseFuzzer

class StatelessFuzz(BaseFuzzer):
    """
    Simple stateless fuzzer, which generates malformed frames
    """
    def __init__(self, target_mac, interface, target_type, attack_mode: StatelessFuzzMode):
        if attack_mode not in StatelessFuzzMode:
            raise ValueError(f"Invalid attack mode: {attack_mode!r}.")
        super().__init__(target_mac, None, interface)
        self.attack_mode = attack_mode
        self.target_type = target_type

    def setup(self):
        # Stateless fuzzing does not need any setup
        pass

    def next_frame(self):
        client_mac = get_random_client_mac()
        type, subtype, payload = get_stateless_attack_params(self.attack_mode)

        if self.target_type == "AP":   
            dot11 = Dot11(type=type, subtype=subtype, addr1=self.target_mac, addr2=client_mac, addr3=self.target_mac)
        else:
            dot11 = Dot11(type=type, subtype=subtype, addr1=self.target_mac, addr2=client_mac, addr3=client_mac)

        if self.attack_mode == StatelessFuzzMode.nav_jamming:
            packet = RadioTap() / payload()
        else:
            packet = RadioTap() / dot11 / payload()
        return packet

    def is_exhausted(self):
        return False