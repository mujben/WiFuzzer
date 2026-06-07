from enum import Enum, auto

class StatelessFuzzMode(Enum):
    ssid_len            = auto()
    ssid_duplication    = auto()
    random_id           = auto()
    vendor_specific     = auto()
    nav_jamming         = auto()
    deauth              = auto()

    action_frame        = auto() 


class SeqFuzzMode(Enum):
    boundary      = auto()  # 0, 1, 4094, 4095
    wrap_around   = auto()  # 4095 → 0 → 1
    duplicate     = auto()  # N, N, N
    backward_small = auto() # N → N-1, N-2, N-3
    backward_large = auto() # np. 2048 → 100 → 0
    forward_large  = auto() # 100 → 2048 → 4000 (kontrola)

class StatefulFuzzMode(Enum):
    handshake_assoc     = auto() # Handshake fuzzing (Auth -> Assoc)