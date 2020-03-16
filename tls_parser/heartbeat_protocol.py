import struct
from enum import IntEnum
from typing import Tuple

from tls_parser.record_protocol import TlsRecord
from tls_parser.record_protocol import TlsRecordHeader
from tls_parser.record_protocol import TlsRecordTypeByte
from tls_parser.record_protocol import TlsSubprotocolMessage
from tls_parser.tls_version import TlsVersionEnum


class TlsHeartbeatTypeByte(IntEnum):
    REQUEST = 0x01
    RESPONSE = 0x02


class TlsHeartbeatMessage(TlsSubprotocolMessage):

    def __init__(
            self,
            hearbeat_type: TlsHeartbeatTypeByte,
            heartbeat_data: bytes) -> None:
        self.type = hearbeat_type
        self.data = heartbeat_data

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> Tuple["TlsHeartbeatMessage", int]:
        raise NotImplementedError()

    def to_bytes(self) -> bytes:
        byte_array = b''
        # Heartbeat message type - 1 byte
        byte_array += struct.pack('B', self.type.value)
        # Heartbeat message length - 2 bytes
        byte_array += struct.pack('!H', len(self.data))
        # Heartbead message data
        byte_array += self.data
        # Padding is not handled
        return byte_array


class TlsHeartbeatRequestRecord(TlsRecord):
    """https://tools.ietf.org/html/rfc6520.
    struct {
      HeartbeatMessageType type;
      uint16 payload_length;
      opaque payload[HeartbeatMessage.payload_length];
      opaque padding[padding_length];
    } HeartbeatMessage;
    """

    def __init__(
            self,
            record_header: TlsRecordHeader,
            heartbeat_message: TlsHeartbeatMessage) -> None:
        super(TlsHeartbeatRequestRecord, self).__init__(
            record_header, [heartbeat_message])

    @classmethod
    def from_parameters(
            cls,
            tls_version: TlsVersionEnum,
            heartbeat_data: bytes) -> "TlsHeartbeatRequestRecord":
        message = TlsHeartbeatMessage(
            TlsHeartbeatTypeByte.REQUEST, heartbeat_data)
        record_header = TlsRecordHeader(
            TlsRecordTypeByte.HEARTBEAT, tls_version, message.size)
        return TlsHeartbeatRequestRecord(record_header, message)

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> Tuple["TlsHeartbeatRequestRecord", int]:
        raise NotImplementedError()
