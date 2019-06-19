import struct
import socket
from .packing_tools import bytes_to_short, bytes_to_integer
from .ip import IP4Prefix, IP4Address
from .ip import IP6Prefix, IP6Address
from .chopper import Chopper
from .tlv import parse_tlv, pack_tlv
from io import BytesIO
from itertools import chain
from collections import OrderedDict

class LdpMessage(object):
    HELLO_MESSAGE = 0x100
    INIT_MESSAGE = 0x200
    KEEPALIVE_MESSAGE = 0x201
    ADDRESS_MESSAGE = 0x300

class LdpGenericMessage(LdpMessage):
    def __init__(self, message_type, message_id, tlvs):
        self.message_type = message_type
        self.message_id = message_id
        self.tlvs = tlvs

    @classmethod
    def parse(cls, message_type, serialised_message):
        message_id, = struct.unpack(
            "!I",
            serialised_message[:4]
        )
        serialised_tlvs = serialised_message[4:]
        tlvs = parse_tlvs(serialised_tlvs)
        return cls(message_type, message_id, tlvs)

    def pack(self):
        packed_message_body = struct.pack(
            "!I",
            self.message_id
        ) + pack_tlvs(self.tlvs)
        message_length = len(packed_message_body)
        packed_message_header = struct.pack(
            "!HH",
            self.message_type,
            message_length
        )

        return packed_message_header + packed_message_body

    def __str__(self):
        return "LdpGenericMessage: Type: %s, ID: %s, TLVs: %s" % (
            self.message_type,
            self.message_id,
            self.tlvs
            )

PARSERS = {}

class LdpMessageParser(object):
    def __init__(self):
        pass

    def parse(self, serialised_message):
        message_type, message_length = struct.unpack("!HH", serialised_message[:4])
        print("Message type: %s, length: %s" % (message_type, message_length))
        if message_type in PARSERS:
            return PARSERS[message_type](serialised_message[4:])

        return LdpGenericMessage.parse(message_type, serialised_message[4:])

def register_parser(cls):
    PARSERS[cls.MSG_TYPE] = cls.parse
    return cls

def parse_tlvs(serialised_tlvs):
    return OrderedDict([parse_tlv(x) for x in Chopper(4, 2, 0, BytesIO(serialised_tlvs))])

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
        generic_message = LdpGenericMessage.parse(cls.MSG_TYPE, serialised_message)
        return cls(generic_message.message_id, generic_message.tlvs)

    def pack(self):
        return LdpGenericMessage(self.MSG_TYPE, self.message_id, self.tlvs).pack()

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

    def build_common_tlvs(self):
        # handle common TLVs
        common_session_parameters = struct.pack(
            "!HHBBH6s",
            self.protocol_version, self.keepalive_time, self.flags, self.path_vector_limit, self.max_pdu_length, self.receiver_ldp_identifier
        )

        return OrderedDict([(0x0500, common_session_parameters)])

    @classmethod
    def parse(cls, serialised_message):
        generic_message = LdpGenericMessage.parse(cls.MSG_TYPE, serialised_message)

        # handle common TLVs
        common_session_parameters = generic_message.tlvs.pop(0x0500)
        protocol_version, keepalive_time, flags, path_vector_limit, max_pdu_length, receiver_ldp_identifier = struct.unpack(
            "!HHBBH6s", common_session_parameters
        )

        return cls(generic_message.message_id, protocol_version, keepalive_time, flags, path_vector_limit, max_pdu_length, receiver_ldp_identifier, generic_message.tlvs)

    def pack(self):
        combined_tlvs = OrderedDict(chain(self.build_common_tlvs().items(), self.tlvs.items()))

        return LdpGenericMessage(self.MSG_TYPE, self.message_id, combined_tlvs).pack()

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

@register_parser
class LdpAddressMessage(LdpMessage):
    MSG_TYPE = LdpMessage.ADDRESS_MESSAGE

    def __init__(self, message_id, tlvs):
        self.message_id = message_id
        self.tlvs = tlvs

    @classmethod
    def parse(cls, serialised_message):
        generic_message = LdpGenericMessage.parse(cls.MSG_TYPE, serialised_message)
        return cls(generic_message.message_id, generic_message.tlvs)

    def pack(self):
        return LdpGenericMessage(self.MSG_TYPE, self.message_id, self.tlvs).pack()

    def __str__(self):
        return "LdpAddressMessage: ID: %s, TLVs: %s" % (
            self.message_id,
            self.tlvs
            )

@register_parser
class LdpKeepaliveMessage(LdpMessage):
    MSG_TYPE = LdpMessage.KEEPALIVE_MESSAGE

    def __init__(self, message_id, tlvs):
        self.message_id = message_id
        self.tlvs = tlvs

    @classmethod
    def parse(cls, serialised_message):
        generic_message = LdpGenericMessage.parse(cls.MSG_TYPE, serialised_message)
        return cls(generic_message.message_id, generic_message.tlvs)

    def pack(self):
        return LdpGenericMessage(self.MSG_TYPE, self.message_id, self.tlvs).pack()

    def __str__(self):
        return "LdpKeepaliveMessage: ID: %s, TLVs: %s" % (
            self.message_id,
            self.tlvs
            )
