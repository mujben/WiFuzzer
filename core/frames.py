# Frame factory for the fuzzer. This module contains malformed frames to be sent.

import random
from scapy.all import Dot11, Dot11Elt, Dot11Deauth, Dot11AssoReq, Dot11ProbeResp, RandString, Raw

from core.enums import StatelessFuzzMode, SeqFuzzMode, HandshakeFuzzMode, StatefulFuzzMode

def get_base():
    return Dot11Elt(ID=0, info="") / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")

def get_random_client_mac():
    return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

def get_random_oui():
    """
    Get random Organizationally Unique Identifier from a choice of
    Microsoft, Ruckus Wireless, Ralink / MediaTek, Atheros, Qualcomm, Realtek, Wi-Fi Alliance
    """
    return random.choice([b'\x00\x50\xf2', b'\x00\x13\x92', b'\x00\x0c\x43', b'\x00\x03\x7f', b'\x00\xa0\xc6', b'\x00\xe0\x4c',b'\x50\x6f\x9a'])

# Stateless Fuzz frames

def _get_ssid_too_long():
    random_len = random.randint(0, 30)
    payload = random.randbytes(500)
    return Raw(load=b'\x00' + bytes([random_len]) + payload)

def _get_ssid_duplication():
    ssid = "TestSSID"
    return Dot11Elt(ID=0, len=len(ssid), info=ssid) / Dot11Elt(ID=0, len=len(ssid), info=ssid) / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")

def _get_random_id():
    rid = random.randint(0, 255)
    return Dot11Elt(ID=rid, len=random.randint(150, 255), info=RandString(10))

def _get_vendor_specific():
    random_len = random.randint(3, 255)
    base = get_base()
    payload = get_random_oui() + random.randbytes(997)
    return Dot11Elt(ID=221, len=random_len, info=payload) / base

def _get_nav_jamming():
    duration = random.randint(10000, 65535)
    return Dot11(type=1, subtype=12, ID=duration, addr1="ff:ff:ff:ff:ff:ff")

def _get_deauth():
    reason_code = random.randint(0, 65535)
    return Dot11Deauth(reason=reason_code)

def _get_probe_resp_overflow():
    base = Dot11ProbeResp(timestamp=random.randint(0, 99999999), beacon_interval=0x100, cap=0x2104)
    ssid_tag = Dot11Elt(ID=0, len=random.randint(0, 30), info=random.randbytes(500))
    rates_tag = Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")
    return base / ssid_tag /rates_tag

def _get_probe_resp_vendor():
    base = Dot11ProbeResp(timestamp=random.randint(0, 99999999), beacon_interval=0x100, cap=0x2104)
    ssid_tag = Dot11Elt(ID=0, len=21, info="Probe response vendor")
    payload = get_random_oui() + random.randbytes(252)
    vendor_tag = Dot11Elt(ID=221, len=255, info=payload)
    return base / ssid_tag / vendor_tag

def _get_probe_resp_csa():
    """Channel switch attack. Force client to change its channel into non-existent one (switch mode = 1, channel = 255, switch count = 255)"""
    base = Dot11ProbeResp(timestamp=random.randint(0, 99999999), beacon_interval=0x100, cap=0x2104)
    ssid_tag = Dot11Elt(ID=0, len=29, info="Probe response channel switch")
    csa_tag = Dot11Elt(ID=37, len=3, info=b"\x01\xff\xff")
    return base / ssid_tag / csa_tag

def _get_public_action_crash():
    """20/40 MHz coexistency management"""
    category = b'\x04'  # Public Action
    action = b'\x00'    # 20/40 BSS Coexistence Management
    payload = random.randbytes(100)
    return Raw(load=category + action + payload)

STATELESS_ATTACKS = {
    StatelessFuzzMode.ssid_len: (0, 4, _get_ssid_too_long),
    StatelessFuzzMode.ssid_duplication: (0, 4, _get_ssid_duplication),
    StatelessFuzzMode.random_id: (0, 4, _get_random_id),
    StatelessFuzzMode.vendor_specific: (0, 4, _get_vendor_specific),
    StatelessFuzzMode.nav_jamming: (1, 12, _get_nav_jamming),
    StatelessFuzzMode.deauth: (0, 12, _get_deauth),

    StatelessFuzzMode.probe_resp_overflow: (0, 5, _get_probe_resp_overflow),
    StatelessFuzzMode.probe_resp_vendor: (0, 5, _get_probe_resp_vendor),
    StatelessFuzzMode.probe_resp_csa: (0, 5, _get_probe_resp_csa),
    StatelessFuzzMode.public_action_crash: (0, 13, _get_public_action_crash)
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

def _get_txop_assoc_overflow(ssid: str):
    """Generates malformed TXOP in WMM tags during Association Request, vendor specific field."""
    base = Dot11AssoReq(cap=0x1101, listen_interval=0x0003)
    essid = Dot11Elt(ID=0, info=ssid)
    rates = Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")

    oui_wmm = get_random_oui()
    wmm_payload = random.randbytes(random.randint(50, 255))
    fuzzed_wmm = Dot11Elt(ID=221, len=len(oui_wmm + wmm_payload), info=oui_wmm + wmm_payload)
    
    return base / essid / rates / fuzzed_wmm

def _get_multiple_rsn_contradictory(ssid: str):
    """Generates two or more contradictory rsn types."""
    base = Dot11AssoReq(cap=0x1101, listen_interval=0x0003)
    essid = Dot11Elt(ID=0, info=ssid)
    rates = Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")

    version = b"\x01\x00"
    group_cipher = b"\x00\x0f\xac\x04"
    count_int = random.randint(1, 4)
    pairwise_count = bytes([count_int]) + b'\x00'
    # cipher list
    pairwise_list = [
        b"\x00\x0f\xac\x02", # TKIP (WPA)
        b"\x00\x0f\xac\x04", # CCMP (WPA2)
        b"\x00\x0f\xac\x08", # GCMP-256 (WPA3)
        b"\xff\xff\xff\xff"  # garbage
        ]
    # authentication and key management
    akm_count = pairwise_count
    akm_list = [
        b"\x00\x0f\xac\x02", # WPA2 PSK
        b"\x00\x0f\xac\x08", # WPA3 SAE
        b"\x00\x0f\xac\x03", # 802.1x with sha1
        b"\xde\xad\xbe\xff"  # garbage
    ]
    cipher_bytes = bytes(0)
    akm_bytes = bytes(0)
    for i in range(count_int):
        cipher_bytes += pairwise_list[i]
        akm_bytes += akm_list[i]
    rsn_payload = version + group_cipher + pairwise_count + cipher_bytes + akm_count + akm_bytes
    fuzzed_rsn = Dot11Elt(ID=48, len=len(rsn_payload), info=rsn_payload)
    return base / essid / rates / fuzzed_rsn

HANDSHAKE_ATTACKS = {
    HandshakeFuzzMode.handshake_assoc: (0, 0, _get_fuzzed_assoc_req),
    HandshakeFuzzMode.txop_assoc: (0, 0, _get_txop_assoc_overflow),
    HandshakeFuzzMode.rsn_conflict: (0, 0, _get_multiple_rsn_contradictory)
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

    return Raw(load=category + action + dialog_token + malformed_ie)

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

    oui = get_random_oui()
    vendor_action = random.randbytes(1)
    vendor_payload = random.randbytes(random.randint(10, 500))

    return Raw(load=category + oui + vendor_action + vendor_payload)

def _get_txop_addts_exhaustion():
    """Generates malformed ADDTS (Add Traffic Stream), targetting time limits of TXOP mechanism and throughput (802.11e)"""
    category = b'\x11'  # QoS Action
    action = b'\x00'    # ADDTS Request
    
    dialog_token = random.randbytes(1)
    # Traffic Specification parameters
    tspec_id = b'\x0d'
    tspec_len = random.randint(100, 255)
    tspec_fuzzed_params = random.randbytes(tspec_len)
    tspec_element = tspec_id + bytes([tspec_len]) + tspec_fuzzed_params
    
    return Raw(load=category + action + dialog_token + tspec_element)

STATEFUL_ATTACKS = {
    StatefulFuzzMode.addba_buffer_overflow: (0, 13, _get_addba_buffer_overflow),
    StatefulFuzzMode.radio_measurement_oob: (0, 13, _get_radio_measurement_oob),
    StatefulFuzzMode.wnm_bss_transition: (0, 13, _get_wnm_bss_transition),
    StatefulFuzzMode.action_frame: (0, 13, _get_vendor_action_crash),
    StatefulFuzzMode.txop_addts: (0, 13, _get_txop_addts_exhaustion)
}

def get_stateful_attack_params(mode: StatefulFuzzMode):
    return STATEFUL_ATTACKS[mode]