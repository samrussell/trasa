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
        expected_tlvs = {
            0x0400 : build_byte_string("002dc000"),
            0x0401 : build_byte_string("ac1a0165"),
            0x0402 : build_byte_string("00000001"),
        }
        self.assertEqual(message.message_id, 8)
        self.assertEqual(message.tlvs, expected_tlvs)
        self.assertEqual(len(message.tlvs), 3)

    def test_hello_message_packs(self):
        expected_serialised_message = build_byte_string("0100001c0000000804000004002dc00004010004ac1a01650402000400000001")
        tlvs = {
            0x0400 : build_byte_string("002dc000"),
            0x0401 : build_byte_string("ac1a0165"),
            0x0402 : build_byte_string("00000001"),
        }
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
        expected_tlvs = {
            0x8506 : build_byte_string("80"),
            0x850b : build_byte_string("80"),
            0x8603 : build_byte_string("80")
        }
        self.assertEqual(message.message_id, 48)
        self.assertEqual(message.tlvs, expected_tlvs)
        # TODO: handle common TLVs differently somehow...
        self.assertEqual(message.protocol_version, 1)
        self.assertEqual(message.keepalive_time, 180)
        self.assertEqual(message.path_vector_limit, 0)
        self.assertEqual(message.max_pdu_length, 0)
        self.assertEqual(message.receiver_ldp_identifier, build_byte_string("ac1a016a0000"))
