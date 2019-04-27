from trasa.chopper import Chopper
import struct
import unittest
from io import BytesIO

class ChopperTestCase(unittest.TestCase):
    def test_tlv_chop(self):
        serialised_data = struct.pack("!HH10s",
            0x1234,
            10,
            b"ten bytes!",
        )
        input_stream = BytesIO(serialised_data)
        serialised_message = Chopper(4, 2, 0, input_stream).next()

        self.assertEqual(serialised_message, serialised_data)

    def test_tlv_with_trailing_data(self):
        serialised_data = struct.pack("!HH10s",
            0x1234,
            10,
            b"ten bytes!",
        )
        input_stream = BytesIO(serialised_data + b"extra data")
        serialised_message = Chopper(4, 2, 0, input_stream).next()

        self.assertEqual(serialised_message, serialised_data)

    def test_tlv_eof(self):
        serialised_data = struct.pack("!HH10s",
            0x1234,
            10,
            b"ten bytes!",
        )
        input_stream = BytesIO(serialised_data)
        chopper = Chopper(4, 2, 0, input_stream)
        serialised_messages = list(chopper)

        self.assertEqual(serialised_messages, [serialised_data])
