import struct
import socket
from .packing_tools import bytes_to_short, bytes_to_integer
from .ip import IP4Prefix, IP4Address
from .ip import IP6Prefix, IP6Address
from .chopper import Chopper
from .tlv import parse_tlv, pack_tlv
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
    return dict([parse_tlv(x) for x in Chopper(4, 2, 0, BytesIO(serialised_tlvs))])

def pack_tlvs(tlvs):
    return b"".join([pack_tlv(key, value) for key, value in tlvs.items()])

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
        return "LdpHelloMessage: ID: %s, TLVs: %s" % (
            self.message_id,
            self.tlvs
            )

@register_parser
class LdpInitialisationMessage(LdpMessage):
    MSG_TYPE = LdpMessage.INIT_MESSAGE

    def __init__(self, message_id, protocol_version, keepalive_time, flags, path_vector_limit, max_pdu_length, receiver_ldp_identifier, tlvs):
        self.message_id = message_id
        self.protocol_version = protocol_version
        self.keepalive_time = keepalive_time
        self.flags = flags
        self.path_vector_limit = path_vector_limit
        self.max_pdu_length = max_pdu_length
        self.receiver_ldp_identifier = receiver_ldp_identifier
        self.tlvs = tlvs

    @classmethod
    def parse(cls, serialised_message):
        message_id, = struct.unpack(
            "!I",
            serialised_message[:4]
        )
        serialised_tlvs = serialised_message[4:]
        tlvs = parse_tlvs(serialised_tlvs)

        # handle common TLVs
        common_session_parameters = tlvs.pop(0x0500)
        protocol_version, keepalive_time, flags, path_vector_limit, max_pdu_length, receiver_ldp_identifier = struct.unpack(
            "!HHBBH6s", common_session_parameters
        )

        return cls(message_id, protocol_version, keepalive_time, flags, path_vector_limit, max_pdu_length, receiver_ldp_identifier, tlvs)

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
        return "LdpInitialisationMessage: ID: %s, Protocol version: %s, Keepalive time: %s, Flags: %s, PVLim: %s, Max PDU Length: %s, Receiver LDP ID: %s, TLVs: %s" % (
            self.message_id,
            self.protocol_version,
            self.keepalive_time,
            self.flags,
            self.path_vector_limit,
            self.max_pdu_length,
            self.receiver_ldp_identifier,
            self.tlvs
            )
