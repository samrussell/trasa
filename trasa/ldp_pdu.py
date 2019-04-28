import struct
import socket
from .packing_tools import bytes_to_short, bytes_to_integer
from .chopper import Chopper
from .ldp_message import LdpMessageParser
from io import BytesIO

def parse_messages(serialised_messages):
    parser = LdpMessageParser()
    messages = []
    for serialised_message in Chopper(4, 2, 0, BytesIO(serialised_messages)):
        message = parser.parse(serialised_message)
        messages.append(message)

    return messages

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


    def __str__(self):
        return "LdpPdu: Version %s, LSR ID: %s, Label space ID: %s, Messages: %s" % (
            self.version,
            self.lsr_id,
            self.label_space_id,
            [str(x) for x in self.messages])

def parse_ldp_pdu(serialised_pdu):
    version, pdu_length, lsr_id, label_space_id  = struct.unpack("!HHIH", serialised_pdu[:LdpPdu.HEADER_LENGTH])
    serialised_messages = serialised_pdu[LdpPdu.HEADER_LENGTH:]
    messages = parse_messages(serialised_messages)
    return LdpPdu(version, lsr_id, label_space_id, messages)
