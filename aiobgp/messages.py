import sys
import struct
import math


"""
aiobgp.messages - Serialization and deserialization of BGP messages in an independent way.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``aiobgp.messages`` module provides functions for serializing and deserializing BGP messages.
It has no dependency on any particular event-loop and can be used to create adaptors to other event
loops than AsyncIO.
"""


BGP_MESSAGE_HEADERLEN = 0x13


BGP_MESSAGE_NIL = 0x0
BGP_MESSAGE_OPEN = 0x1
BGP_MESSAGE_UPDATE = 0x2
BGP_MESSAGE_NOTIFICATION = 0x3
BGP_MESSAGE_KEEPALIVE = 0x4


BGP_MESSAGE_MARKER = b'\xff' * 16


class BGPMessage:
    """The BGPMessage class provides an abstract view of a BGP message, given a collection of bytes.  It
    also handles rendering a message back to a collection of bytes, through the ``encode()`` function.  Messages
    are decoded via the ``decode()`` function."""
    __messagetype__ = BGP_MESSAGE_NIL
    def __init__(self):
        self.length = BGP_MESSAGE_HEADERLEN
        self.msg_type = self.__messagetype__

    def encode_header(self, data):
        assert self.__messagetype__ > BGP_MESSAGE_NIL

        length = len(data) + BGP_MESSAGE_HEADERLEN
        return BGP_MESSAGE_MARKER + struct.pack('!H', length) + bytearray([self.__messagetype__]) + data

    def encode(self):
        return self.encode_header(b'')

    @staticmethod
    def decode_header(data):
        if len(data) < 19:
            return None

        length, msg_type = struct.unpack_from('!HB', data, offset=16)
        return {'length': length, 'msg_type': msg_type}

    @classmethod
    def decode(cls, data):
        if len(data) < 19:
            return None

        header = BGPMessage.decode_header(data)
        if not header:
            return None

        out = cls()
        out.length = header['length']
        out.msg_type = header['msg_type']
        return out

    def __repr__(self):
        return "<{0}: type={1} length={2}>".format(self.__class__.__name__, self.msg_type, self.length)


class OpenMessage(BGPMessage):
    __messagetype__ = BGP_MESSAGE_OPEN


class UpdateMessage(BGPMessage):
    __messagetype__ = BGP_MESSAGE_UPDATE


class NotificationMessage(BGPMessage):
    __messagetype__ = BGP_MESSAGE_NOTIFICATION


class KeepAliveMessage(BGPMessage):
    __messagetype__ = BGP_MESSAGE_KEEPALIVE


message_types = {
    BGP_MESSAGE_OPEN: OpenMessage,
    BGP_MESSAGE_UPDATE: UpdateMessage,
    BGP_MESSAGE_NOTIFICATION: NotificationMessage,
    BGP_MESSAGE_KEEPALIVE: KeepAliveMessage
}


if __name__ == '__main__':
    print(repr(KeepAliveMessage()))
    print(repr(KeepAliveMessage().encode()))

    assert repr(KeepAliveMessage()) == repr(KeepAliveMessage.decode(KeepAliveMessage().encode()))
