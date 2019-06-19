import struct

def bytes_to_short(bytes_):
    short, = struct.unpack("!H", bytes_)
    return short

def bytes_to_integer(bytes_):
    integer, = struct.unpack("!I", bytes_)
    return integer

def short_to_bytes(short):
    bytes_ = struct.pack("!H", short)
    return bytes_

def integer_to_bytes(integer):
    bytes_ = struct.pack("!I", integer)
    return bytes_
