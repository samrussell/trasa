from trasa.ldp_message import LdpMessage, LdpHelloMessage, LdpMessageParser
import socket
import struct
import unittest

def build_byte_string(hex_stream):
    values = [int(x, 16) for x in map(''.join, zip(*[iter(hex_stream)]*2))]
    return struct.pack("!" + "B" * len(values), *values)

class LdpMessageTestCase(unittest.TestCase):
    def test_hello_message_parses(self):
        serialised_message = build_byte_string("0100001c0000000804000004002dc00004010004ac1a01650402000400000001")
        message = LdpMessageParser().parse(serialised_message)
        expected_tlvs = [
            build_byte_string("04000004002dc000"),
            build_byte_string("04010004ac1a0165"),
            build_byte_string("0402000400000001")
        ]
        self.assertEqual(message.message_id, 8)
        self.assertEqual(message.tlvs, expected_tlvs)
        self.assertEqual(len(message.tlvs), 3)

    def test_single_message_packs(self):
        expected_serialised_message = build_byte_string("0100001c0000000804000004002dc00004010004ac1a01650402000400000001")
        tlvs = [
            build_byte_string("04000004002dc000"),
            build_byte_string("04010004ac1a0165"),
            build_byte_string("0402000400000001")
        ]
        message = LdpHelloMessage(8, tlvs)
        serialised_message = message.pack()
        self.assertEqual(serialised_message, expected_serialised_message)
