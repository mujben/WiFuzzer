from enum import Enum, auto

class SeqFuzzMode(Enum):
    BOUNDARY      = auto()  # 0, 1, 4094, 4095
    WRAP_AROUND   = auto()  # 4095 → 0 → 1
    DUPLICATE     = auto()  # N, N, N
    BACKWARD_SMALL = auto() # N → N-1, N-2, N-3
    BACKWARD_LARGE = auto() # np. 2048 → 100 → 0
    FORWARD_LARGE  = auto() # 100 → 2048 → 4000 (kontrola)


class SeqFuzz:
    """
    Stateful sequence number fuzzer with cyclic modes
    """
    SEQUENCES = {
        SeqFuzzMode.BOUNDARY:       [0, 1, 4094, 4095, 0, 1],
        SeqFuzzMode.WRAP_AROUND:    [4093, 4094, 4095, 0, 1, 2],
        SeqFuzzMode.DUPLICATE:      [100, 100, 100, 100, 100],
        SeqFuzzMode.BACKWARD_SMALL: [500, 499, 498, 497, 496, 495],
        SeqFuzzMode.BACKWARD_LARGE: [2048, 1024, 100, 10, 1, 0],
        SeqFuzzMode.FORWARD_LARGE:  [100, 500, 2048, 4000, 4095],
    }

    def __init__(self, mode, tries=10):
        mode = self.SEQUENCES[mode]
        self._seq = list(mode * tries)
        self._idx = 0
        self.crash_log = [] # (previous seq_num, current seq_num)

    def next(self):
        if self._idx >= len(self._seq):
            return 0
        seq_num = self._seq[self._idx]
        self._idx += 1
        return seq_num # raw value
    
    def is_running(self):
        return self._idx < len(self._seq)
