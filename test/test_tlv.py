from trasa.tlv import parse_tlv, pack_tlv
import socket
import struct
import unittest

def build_byte_string(hex_stream):
    values = [int(x, 16) for x in map(''.join, zip(*[iter(hex_stream)]*2))]
    return struct.pack("!" + "B" * len(values), *values)

class TlvMessageTestCase(unittest.TestCase):
    def test_tlv_parses(self):
        tlv = build_byte_string("04000004002dc000")
        key, value = parse_tlv(tlv)
        self.assertEqual(key, 0x0400)
        self.assertEqual(value, build_byte_string('002dc000'))

    def test_tlv_packs(self):
        expected_tlv = build_byte_string("04000004002dc000")
        tlv = pack_tlv(0x0400, build_byte_string('002dc000'))
        self.assertEqual(tlv, expected_tlv)