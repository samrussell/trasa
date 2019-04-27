import struct
from .error import SocketClosedError

class Chopper(object):
    SIZE_TO_PACK_STRING = {
        1: "!B",
        2: "!H",
        4: "!I"
    }
    def __init__(self, header_length, length_offset, length_adjustment, input_stream):
        self.header_length = header_length
        self.length_offset = length_offset
        self.length_adjustment = length_adjustment
        self.input_stream = input_stream

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        # TODO handle when stream runs out
        serialised_header = self.input_stream.read(self.header_length)
        if len(serialised_header) == 0:
            # special case - clean end
            raise StopIteration()
        if len(serialised_header) < self.header_length:
            raise SocketClosedError("Tried to read %d bytes but only got %d" % (self.header_length, len(serialised_header)))

        length_size = self.header_length - self.length_offset
        body_length, = struct.unpack(self.SIZE_TO_PACK_STRING[length_size], serialised_header[self.length_offset:])
        extra_data_length = body_length - self.length_adjustment
        if extra_data_length > 0:
            serialised_body = self.input_stream.read(extra_data_length)
            if len(serialised_body) < extra_data_length:
                raise SocketClosedError("Tried to read %d bytes but only got %d" % (extra_data_length, len(serialised_header)))
        else:
            serialised_body = b""

        return serialised_header + serialised_body
