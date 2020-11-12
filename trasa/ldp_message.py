import struct
import socket
from .packing_tools import bytes_to_short, bytes_to_integer, short_to_bytes, integer_to_bytes
from .chopper import Chopper
from .tlv import parse_tlv, pack_tlv
from .identifier import Identifier, parse_identifier
from io import BytesIO
from itertools import chain
from collections import OrderedDict
from ipaddress import IPv4Address, IPv4Network

class LdpMessage(object):
    NOTIFICATION_MESSAGE = 0x001
    HELLO_MESSAGE = 0x100
    INIT_MESSAGE = 0x200
    KEEPALIVE_MESSAGE = 0x201
    ADDRESS_MESSAGE = 0x300
    LABEL_MAPPING_MESSAGE = 0x400

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
class LdpNotificationMessage(LdpMessage):
    MSG_TYPE = LdpMessage.NOTIFICATION_MESSAGE

    def __init__(self, message_id, fatal, forward, status_data, error_message_id, error_message_type, tlvs):
        self.message_id = message_id
        self.fatal = fatal
        self.forward = forward
        self.status_data = status_data
        self.error_message_id = error_message_id
        self.error_message_type = error_message_type
        self.tlvs = tlvs

    def build_common_tlvs(self):
        # handle common TLVs
        status_code = self.status_data
        if self.fatal:
            status_code += 0x80000000
        if self.forward:
            status_code += 0x40000000

        status_tlv = struct.pack("!IIH", status_code, self.error_message_id, self.error_message_type)
        return OrderedDict([
            (0x0300, status_tlv)
        ])

    @classmethod
    def parse(cls, serialised_message):
        generic_message = LdpGenericMessage.parse(cls.MSG_TYPE, serialised_message)

        # handle common TLVs
        # TODO handle status TLV when it should be forwarded
        status_tlv = generic_message.tlvs.pop(0x0300)
        status_code, error_message_id, error_message_type = struct.unpack("!IIH", status_tlv)
        fatal = (status_code & 0x80000000) >> 31
        forward = (status_code & 0x40000000) >> 30
        status_data = (status_code & 0x3FFFFFFF)

        return cls(generic_message.message_id, fatal, forward, status_data, error_message_id, error_message_type, generic_message.tlvs)

    def pack(self):
        combined_tlvs = OrderedDict(chain(self.build_common_tlvs().items(), self.tlvs.items()))

        return LdpGenericMessage(self.MSG_TYPE, self.message_id, combined_tlvs).pack()

    def __str__(self):
        return "LdpNotificationMessage: ID: %s, fatal: %s, forward: %s, status_data: %s, error_message_id: %s, error_message_type: %s, TLVs: %s" % (
            self.message_id,
            self.fatal,
            self.forward,
            self.status_data,
            self.error_message_id,
            self.error_message_type,
            self.tlvs
            )

@register_parser
class LdpHelloMessage(LdpMessage):
    MSG_TYPE = LdpMessage.HELLO_MESSAGE

    def __init__(self, message_id, hold_time, targeted, request_targeted, tlvs):
        self.message_id = message_id
        self.hold_time = hold_time
        self.targeted = targeted
        self.request_targeted = request_targeted
        self.tlvs = tlvs

    def build_common_tlvs(self):
        # handle common TLVs
        flags = 0
        if self.targeted:
            flags += 0x8000
        if self.request_targeted:
            flags += 0x4000

        common_hello = struct.pack("!HH", self.hold_time, flags)
        return OrderedDict([
            (0x0400, common_hello)
        ])

    @classmethod
    def parse(cls, serialised_message):
        generic_message = LdpGenericMessage.parse(cls.MSG_TYPE, serialised_message)

        # handle common TLVs
        common_hello = generic_message.tlvs.pop(0x0400)
        hold_time, flags = struct.unpack("!HH", common_hello)
        targeted = (0x8000 & flags) > 0
        request_targeted = (0x4000 & flags) > 0

        return cls(generic_message.message_id, hold_time, targeted, request_targeted, generic_message.tlvs)

    def pack(self):
        combined_tlvs = OrderedDict(chain(self.build_common_tlvs().items(), self.tlvs.items()))

        return LdpGenericMessage(self.MSG_TYPE, self.message_id, combined_tlvs).pack()

    def __str__(self):
        return "LdpHelloMessage: ID: %s, Hold time: %s, Targeted: %s, Request targeted: %s, TLVs: %s" % (
            self.message_id,
            self.hold_time,
            self.targeted,
            self.request_targeted,
            self.tlvs
            )

@register_parser
class LdpInitialisationMessage(LdpMessage):
    MSG_TYPE = LdpMessage.INIT_MESSAGE

    def __init__(self, message_id, protocol_version, keepalive_time, flags, path_vector_limit, max_pdu_length, router_id, label_space_id, tlvs):
        self.message_id = message_id
        self.protocol_version = protocol_version
        self.keepalive_time = keepalive_time
        self.flags = flags
        self.path_vector_limit = path_vector_limit
        self.max_pdu_length = max_pdu_length
        self.receiver_ldp_identifier = Identifier(router_id, label_space_id)
        self.tlvs = tlvs

    def build_common_tlvs(self):
        # handle common TLVs
        common_session_parameters = struct.pack(
            "!HHBBH6s",
            self.protocol_version, self.keepalive_time, self.flags, self.path_vector_limit, self.max_pdu_length, self.receiver_ldp_identifier.pack()
        )

        return OrderedDict([(0x0500, common_session_parameters)])

    @classmethod
    def parse(cls, serialised_message):
        generic_message = LdpGenericMessage.parse(cls.MSG_TYPE, serialised_message)

        # handle common TLVs
        common_session_parameters = generic_message.tlvs.pop(0x0500)
        protocol_version, keepalive_time, flags, path_vector_limit, max_pdu_length, packed_receiver_ldp_identifier = struct.unpack(
            "!HHBBH6s", common_session_parameters
        )
        receiver_ldp_identifier = parse_identifier(packed_receiver_ldp_identifier)

        return cls(generic_message.message_id, protocol_version, keepalive_time, flags, path_vector_limit, max_pdu_length, receiver_ldp_identifier.router_id, receiver_ldp_identifier.label_space_id, generic_message.tlvs)

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

def unpack_address_list_tlv(packed_addresses):
    family = bytes_to_short(packed_addresses[:2])
    if family != 1:
        raise Exception("Address family not supported %s" % packed_addresses)
    body = packed_addresses[2:]
    addresses = []
    while body:
        data = body[:4]
        body = body[4:]
        addresses.append(IPv4Address(data))
    return addresses

def pack_address_list_tlv(addresses):
    # assume IPv4
    data_chunks = []
    data_chunks.append(short_to_bytes(1))
    for address in addresses:
        data_chunks.append(integer_to_bytes(int(address)))
    return b''.join(data_chunks)

@register_parser
class LdpAddressMessage(LdpMessage):
    MSG_TYPE = LdpMessage.ADDRESS_MESSAGE

    def __init__(self, message_id, addresses, tlvs):
        self.message_id = message_id
        self.addresses = addresses
        self.tlvs = tlvs

    def build_common_tlvs(self):
        return OrderedDict([
            (0x0101, pack_address_list_tlv(self.addresses))
        ])

    @classmethod
    def parse(cls, serialised_message):
        generic_message = LdpGenericMessage.parse(cls.MSG_TYPE, serialised_message)

        # handle common TLVs
        packed_addresses = generic_message.tlvs.pop(0x0101)
        addresses = unpack_address_list_tlv(packed_addresses)

        return cls(generic_message.message_id, addresses, generic_message.tlvs)

    def pack(self):
        combined_tlvs = OrderedDict(chain(self.build_common_tlvs().items(), self.tlvs.items()))
        return LdpGenericMessage(self.MSG_TYPE, self.message_id, combined_tlvs).pack()

    def __str__(self):
        return "LdpAddressMessage: ID: %s, Addresses: %s, TLVs: %s" % (
            self.message_id,
            self.addresses,
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

def prefix_byte_length(prefix_length):
    # whole bytes
    byte_length = prefix_length // 8
    # plus pad to a whole byte for remainder
    if prefix_length % 8:
        byte_length += 1

    return byte_length

def pack_prefix(prefix):
    return prefix.network_address.packed[:prefix_byte_length(prefix.prefixlen)]

def pack_fec(prefix):
    return struct.pack("!BHB", 2, 1, prefix.prefixlen) + pack_prefix(prefix)

def unpack_fec(fec):
    fec_type, address_type, prefix_length = struct.unpack("!BHB", fec[:4])

    if fec_type != 2:
        raise Exception("Got bad FEC type: %s" % fec_type)
    if address_type != 1:
        raise Exception("Got bad address type: %s" % address_type)

    squashed_prefix = fec[4:4+prefix_byte_length(prefix_length)]
    prefix = squashed_prefix + (b'\x00' * (4 - len(squashed_prefix)))
    return IPv4Network(prefix).supernet(new_prefix=prefix_length)

def unpack_fec_tlv(packed_fecs):
    prefixes = []

    while packed_fecs:
        prefix = unpack_fec(packed_fecs)
        packed_fecs = packed_fecs[4+prefix_byte_length(prefix.prefixlen):]
        prefixes.append(prefix)

    return prefixes

def pack_fec_tlv(prefixes):
    # assume IPv4
    data_chunks = []
    for prefix in prefixes:
        data_chunks.append(pack_fec(prefix))
    return b''.join(data_chunks)

@register_parser
class LdpLabelMappingMessage(LdpMessage):
    MSG_TYPE = LdpMessage.LABEL_MAPPING_MESSAGE

    def __init__(self, message_id, prefixes, label, tlvs):
        self.message_id = message_id
        self.prefixes = prefixes
        self.label = label
        self.tlvs = tlvs

    def build_common_tlvs(self):
        # handle common TLVs
        fecs = pack_fec_tlv(self.prefixes)
        packed_label = integer_to_bytes(self.label)
        return OrderedDict([
            (0x0100, fecs),
            (0x0200, packed_label)
        ])

    @classmethod
    def parse(cls, serialised_message):
        generic_message = LdpGenericMessage.parse(cls.MSG_TYPE, serialised_message)

        # handle common TLVs
        fecs = generic_message.tlvs.pop(0x0100)
        packed_label = generic_message.tlvs.pop(0x0200)
        label = bytes_to_integer(packed_label)

        prefixes = unpack_fec_tlv(fecs)

        return cls(generic_message.message_id, prefixes, label, generic_message.tlvs)

    def pack(self):
        combined_tlvs = OrderedDict(chain(self.build_common_tlvs().items(), self.tlvs.items()))

        return LdpGenericMessage(self.MSG_TYPE, self.message_id, combined_tlvs).pack()

    def __str__(self):
        return "LdpLabelMappingMessage: ID: %s, Prefixes: %s, Label: %s, TLVs: %s" % (
            self.message_id,
            self.prefixes,
            self.label,
            self.tlvs
            )
