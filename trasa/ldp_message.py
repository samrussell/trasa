import struct
import socket
from .packing_tools import bytes_to_short, bytes_to_integer
from .ip import IP4Prefix, IP4Address
from .ip import IP6Prefix, IP6Address
from .chopper import Chopper
from io import BytesIO

class LdpMessage(object):
    HELLO_MESSAGE = 0x100
    INIT_MESSAGE = 0x200

PARSERS = {}

class LdpMessageParser(object):
    def __init__(self):
        pass

    def parse(self, serialised_message):
        message_type, message_length = struct.unpack("!HH", serialised_message[:4])
        print("Message type: %s, length: %s" % (message_type, message_length))
        return PARSERS[message_type](serialised_message[4:])

def register_parser(cls):
    PARSERS[cls.MSG_TYPE] = cls.parse
    return cls

def parse_tlvs(serialised_tlvs):
    return list(Chopper(4, 2, 0, BytesIO(serialised_tlvs)))

def pack_tlvs(tlvs):
    return b"".join(tlvs)

@register_parser
class LdpHelloMessage(LdpMessage):
    MSG_TYPE = LdpMessage.HELLO_MESSAGE

    def __init__(self, message_id, tlvs):
        self.message_id = message_id
        self.tlvs = tlvs

    @classmethod
    def parse(cls, serialised_message):
        message_id, = struct.unpack(
            "!I",
            serialised_message[:4]
        )
        serialised_tlvs = serialised_message[4:]
        tlvs = parse_tlvs(serialised_tlvs)
        return cls(message_id, tlvs)

    def pack(self):
        packed_message_body = struct.pack(
            "!I",
            self.message_id
        ) + pack_tlvs(self.tlvs)
        message_length = len(packed_message_body)
        packed_message_header = struct.pack(
            "!HH",
            self.MSG_TYPE,
            message_length
        )

        return packed_message_header + packed_message_body

    def __str__(self):
        return "LdpHelloMessage: ID: %s" % (
            self.message_id
            )
