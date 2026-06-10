# Frame factory for the fuzzer. This module contains malformed frames to be sent.

import random
from scapy.all import Dot11Elt, Dot11Deauth, RandString, Raw
from scapy.all import Dot11AssoReq

from core.enums import StatelessFuzzMode, SeqFuzzMode, HandshakeFuzzMode, StatefulFuzzMode

def get_base():
    return Dot11Elt(ID=0, info="") / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")

def get_random_client_mac():
    return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

# Stateless Fuzz frames

def _get_ssid_too_long():
    random_len = random.randint(0, 255)
    payload = random.randbytes(500)
    return Dot11Elt(ID=0, len=random_len, info=payload) / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")

def _get_ssid_duplication():
    ssid = "TestSSID"
    return Dot11Elt(ID=0, len=len(ssid), info=ssid) / Dot11Elt(ID=0, len=len(ssid), info=ssid) / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")

def _get_random_id():
    rid = random.randint(0, 255)
    return Dot11Elt(ID=rid, len=random.randint(150, 255), info=RandString(10))

def _get_vendor_specific():
    random_len = random.randint(1, 255)
    base = get_base()
    return Dot11Elt(ID=221, len=random_len, info=random.randbytes(1000)) / base

def _get_nav_jamming():
    return random.randint(10000, 65535)

def _get_deauth():
    reason_code = random.randint(0, 65535)
    return Dot11Deauth(reason=reason_code)

STATELESS_ATTACKS = {
    StatelessFuzzMode.ssid_len: (0, 4, _get_ssid_too_long),
    StatelessFuzzMode.ssid_duplication: (0, 4, _get_ssid_duplication),
    StatelessFuzzMode.random_id: (0, 4, _get_random_id),
    StatelessFuzzMode.vendor_specific: (0, 4, _get_vendor_specific),
    StatelessFuzzMode.nav_jamming: (2, 4, _get_nav_jamming),
    StatelessFuzzMode.deauth: (0, 12, _get_deauth)
}

def get_stateless_attack_params(mode: StatelessFuzzMode):
    return STATELESS_ATTACKS[mode]

# Sequence Fuzz frames

SEQ_SEQUENCES = {
    SeqFuzzMode.boundary:       [0, 1, 4094, 4095, 0, 1],
    SeqFuzzMode.wrap_around:    [4093, 4094, 4095, 0, 1, 2],
    SeqFuzzMode.duplicate:      [100, 100, 100, 100, 100],
    SeqFuzzMode.backward_small: [500, 499, 498, 497, 496, 495],
    SeqFuzzMode.backward_large: [2048, 1024, 100, 10, 1, 0],
    SeqFuzzMode.forward_large:  [100, 500, 2048, 4000, 4095],
}

def get_seq_attack_params(mode: SeqFuzzMode):
    return SEQ_SEQUENCES[mode]

# Handshake Fuzz frames

def _get_fuzzed_assoc_req(ssid: str):
    """Generates Association Request with malformed/extra Information Elements."""
    # Base Association Request
    base = Dot11AssoReq(cap=0x1101, listen_interval=0x0003)
    # Adding a mix of valid and fuzzed Information Elements
    essid = Dot11Elt(ID=0, info=ssid)
    rates = Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")
    fuzzed_element = Dot11Elt(ID=random.randint(0, 255), len=random.randint(0, 255), info=RandString(50))
    return base / essid / rates / fuzzed_element

HANDSHAKE_ATTACKS = {
    HandshakeFuzzMode.handshake_assoc: (0, 0, _get_fuzzed_assoc_req)
}

def get_handshake_attack_params(mode: HandshakeFuzzMode):
    return HANDSHAKE_ATTACKS[mode]

# Stateful Fuzz frames

def _get_addba_buffer_overflow():
    """Generates an ADDBA Request frame with an excessively large buffer size to trigger potential overflow."""
    category = b'\x03'  # Block Ack
    action = b'\x00'    # ADDBA Request

    dialog_token = random.randbytes(1)
    fuzzed_params = random.randbytes(6)
    random_padding = random.randbytes(random.randint(0, 100))

    return Raw(load=category + action + dialog_token + fuzzed_params + random_padding)

def _get_radio_measurement_oob():
    """Generates a Radio Measurement Request frame with out-of-bounds parameters."""
    category = b'\x05'  # Radio Measurement
    action = b'\x01'    # Measurement Report

    dialog_token = random.randbytes(1)
    fake_len = random.randint(100, 255)
    malformed_ie = Dot11Elt(ID=39, len=fake_len, info=random.randbytes(10))

    return Raw(load=category + action + dialog_token) / malformed_ie

def _get_wnm_bss_transition():
    """Generates a WNM BSS Transition Management Response with fuzzed status code and neighbor AP mac addresses."""
    category = b'\x0a'  # WNM
    action = b'\x08'    # BSS Transition Management Response

    dialog_token = random.randbytes(1)
    status_code = random.randbytes(1)
    bss_termination_delay = random.randbytes(1)
    neighbor_bssid = random.randbytes(6)

    return Raw(load=category + action + dialog_token + status_code + bss_termination_delay + neighbor_bssid)

def _get_vendor_action_crash():
    """Generates malformed Action Frames (Category 127 is Vendor Specific)."""
    category = b'\x7f'  # Vendor Specific

    oui = random.choice([b'\x00\x50\xf2', b'\x00\x13\x92', b'\x00\x0c\x43'])
    vendor_action = random.randbytes(1)
    vendor_payload = random.randbytes(random.randint(10, 500))

    return Raw(load=category + oui + vendor_action + vendor_payload)

STATEFUL_ATTACKS = {
    StatefulFuzzMode.addba_buffer_overflow: (0, 13, _get_addba_buffer_overflow),
    StatefulFuzzMode.radio_measurement_oob: (0, 13, _get_radio_measurement_oob),
    StatefulFuzzMode.wnm_bss_transition: (0, 13, _get_wnm_bss_transition),
    StatefulFuzzMode.action_frame: (0, 13, _get_vendor_action_crash)
}

def get_stateful_attack_params(mode: StatefulFuzzMode):
    return STATEFUL_ATTACKS[mode]