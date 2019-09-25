import struct
import socket
from ipaddress import IPv4Address
from .packing_tools import bytes_to_short, bytes_to_integer

class Identifier:
    def __init__(self, router_id, label_space_id):
        self.router_id = router_id
        self.label_space_id = label_space_id

    def pack(self):
        return struct.pack("!4sH", IPv4Address(self.router_id).packed, self.label_space_id)

    def __str__(self):
        return "%s:%s" % (self.router_id, self.label_space_id)

def parse_identifier(packed_identifier):
    packed_router_id, label_space_id = struct.unpack("!4sH", packed_identifier)
    router_id = str(IPv4Address(packed_router_id))
    return Identifier(router_id, label_space_id)
