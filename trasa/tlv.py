import struct
import socket
from .packing_tools import bytes_to_short, bytes_to_integer

def pack_tlv(key, value):
    return struct.pack("!HH", key, len(value)) + value

def parse_tlv(tlv):
    key, value_length = struct.unpack("!HH", tlv[:4])
    value = tlv[4:]
    if len(value) != value_length:
        raise Exception("Got TLV with value of bad length: %s" % tlv)
    return key, value
