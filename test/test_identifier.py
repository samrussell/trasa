from trasa.identifier import Identifier, parse_identifier
import socket
import struct
import unittest

def build_byte_string(hex_stream):
    values = [int(x, 16) for x in map(''.join, zip(*[iter(hex_stream)]*2))]
    return struct.pack("!" + "B" * len(values), *values)

class IdentifierMessageTestCase(unittest.TestCase):
    def test_identifier_parses(self):
        packed_identifier = build_byte_string("ac1a01701234")
        identifier = parse_identifier(packed_identifier)
        self.assertEqual(identifier.router_id, "172.26.1.112")
        self.assertEqual(identifier.label_space_id, 4660)

    def test_identifier_packs(self):
        expected_packed_identifier = build_byte_string("ac1a01701234")
        identifier = Identifier("172.26.1.112", 4660)
        packed_identifier = identifier.pack()
        self.assertEqual(packed_identifier, expected_packed_identifier)

    def test_identifer_str(self):
        identifier = Identifier("172.26.1.112", 4660)
        self.assertEqual(str(identifier), "172.26.1.112:4660")
