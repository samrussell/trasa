import struct
import socket
from .packing_tools import bytes_to_short, bytes_to_integer
from .chopper import Chopper
from io import BytesIO

def parse_messages(serialised_messages):
    return list(Chopper(4, 2, 0, BytesIO(serialised_messages)))

def pack_messages(messages):
    return b"".join(messages)

class LdpPdu(object):
    HEADER_LENGTH = 10
    
    def __init__(self, version, lsr_id, label_space_id, messages):
        self.version = version
        self.lsr_id = lsr_id
        self.label_space_id = label_space_id
        self.messages = messages

    def pack(self):
        packed_pdu_body = struct.pack(
            "!IH",
            self.lsr_id,
            self.label_space_id
            ) + pack_messages(self.messages)
        pdu_length = len(packed_pdu_body)
        packed_pdu_header = struct.pack(
            "!HH",
            self.version,
            pdu_length,
        )

        return packed_pdu_header + packed_pdu_body

def parse_ldp_pdu(serialised_pdu):
    version, pdu_length, lsr_id, label_space_id  = struct.unpack("!HHIH", serialised_pdu[:LdpPdu.HEADER_LENGTH])
    serialised_messages = serialised_pdu[LdpPdu.HEADER_LENGTH:]
    messages = parse_messages(serialised_messages)
    return LdpPdu(version, lsr_id, label_space_id, messages)
