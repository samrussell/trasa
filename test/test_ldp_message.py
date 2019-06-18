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

    def test_initialisation_message_parses(self):
        serialised_message = build_byte_string("02000025000000300500000e000100b400000000ac1a016a00008506000180850b0001808603000180")
        # 0200 initialisation message
        # 0025 message length 37
        # 00000030 message id 48
        # 0500000e000100b400000000ac1a016a0000 common session parameters tlv
        # 8506000180 no idea what this tlv is
        # 850b000180 no idea what this tlv is
        # 8603000180 no idea what this tlv is
        message = LdpMessageParser().parse(serialised_message)
        expected_tlvs = [
            build_byte_string("0500000e000100b400000000ac1a016a0000"),
            build_byte_string("8506000180"),
            build_byte_string("850b000180"),
            build_byte_string("8603000180")
        ]
        self.assertEqual(message.message_id, 48)
        self.assertEqual(message.tlvs, expected_tlvs)
