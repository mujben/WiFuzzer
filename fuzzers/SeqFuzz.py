from scapy.all import RadioTap, Dot11
from fuzzers.BaseFuzzer import BaseFuzzer
from core.enums import SeqFuzzMode
from core.frames import get_random_client_mac, get_seq_attack_params, get_base

class SeqFuzz(BaseFuzzer):
    """
    Sequence number fuzzer with cyclic modes
    """
    def __init__(self, target_mac, interface, tries=50):
        super().__init__(target_mac, None, interface)
        self.tries = tries
        self.mode = iter(SeqFuzzMode)
        self.current_sequence = []
        self._idx = 0
        self._load_next_mode()

    def _load_next_mode(self):
        try:
            current_mode = next(self.mode)
            base_list = get_seq_attack_params(current_mode)
            self.current_sequence = base_list * self.tries
            self._idx = 0
            return True
        except StopIteration:
            print("[*] All sequence fuzzing modes exhausted. Stopping fuzzing.")
            return False

    def setup(self):
        # Sequential fuzzing does not need any setup
        pass

    def next_frame(self):
        if self._idx >= len(self.current_sequence):
            if not self._load_next_mode():
                return None
        seq_num = self.current_sequence[self._idx]
        self._idx += 1

        client_mac = get_random_client_mac()
        dot11 = Dot11(type=0, subtype=4, addr1=self.target_mac, addr2=client_mac, addr3=self.target_mac)
        dot11.SC = (seq_num << 4) | 0
        packet = RadioTap() / dot11 / get_base()
        return packet

    # def is_running(self):
    #     return self._idx < len(self.current_sequence)
