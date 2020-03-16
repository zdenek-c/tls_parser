import struct
from enum import IntEnum
from typing import Tuple

from tls_parser.exceptions import NotEnoughData
from tls_parser.exceptions import UnknownTypeByte
from tls_parser.record_protocol import TlsRecord
from tls_parser.record_protocol import TlsRecordHeader
from tls_parser.record_protocol import TlsRecordTypeByte
from tls_parser.record_protocol import TlsSubprotocolMessage
from tls_parser.tls_version import TlsVersionEnum


class TlsAlertSeverityByte(IntEnum):
    WARNING = 0x01
    FATAL = 0x02


class TlsAlertMessage(TlsSubprotocolMessage):

    def __init__(
            self,
            alert_severity: TlsAlertSeverityByte,
            alert_description: int) -> None:
        self.alert_severity = alert_severity
        # Right now the description is just stored as an int instead
        # of a TlsAlertDescriptionByte
        self.alert_description = alert_description

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> Tuple["TlsAlertMessage", int]:
        if len(raw_bytes) < 2:
            raise NotEnoughData()

        alert_severity = TlsAlertSeverityByte(
            struct.unpack("B", raw_bytes[0:1])[0])
        alert_description = struct.unpack("B", raw_bytes[1:2])[0]
        return TlsAlertMessage(alert_severity, alert_description), 2

    def to_bytes(self) -> bytes:
        byte_array = b""
        byte_array += struct.pack("B", self.alert_severity.value)
        byte_array += struct.pack("B", self.alert_description)
        return byte_array


class TlsAlertRecord(TlsRecord):
    def __init__(
            self,
            record_header: TlsRecordHeader,
            alert_message: TlsAlertMessage) -> None:
        super(TlsAlertRecord, self).__init__(record_header, [alert_message])

    @property
    def alert_severity(self) -> TlsAlertSeverityByte:
        """Convenience method to get the severity of the underlying Alert message.

        This makes the assumption that an Alert record only contains one Alert message, which seems to be the case in
        the real world.
        """
        return self.subprotocol_messages[0].alert_severity

    @property
    def alert_description(self) -> int:
        """Convenience method to get the description of the underlying Alert message.

        This makes the assumption that an Alert record only contains one Alert message, which seems to be the case in
        the real world.
        """
        return self.subprotocol_messages[0].alert_description

    @classmethod
    def from_parameters(
            cls,
            tls_version: TlsVersionEnum,
            alert_severity: TlsAlertSeverityByte,
            alert_description: int) -> "TlsAlertRecord":
        alert_message = TlsAlertMessage(alert_severity, alert_description)
        record_header = TlsRecordHeader(
            TlsRecordTypeByte.ALERT, tls_version, alert_message.size)
        return TlsAlertRecord(record_header, alert_message)

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> Tuple["TlsAlertRecord", int]:
        header, len_consumed = TlsRecordHeader.from_bytes(raw_bytes)
        remaining_bytes = raw_bytes[len_consumed::]

        if header.type != TlsRecordTypeByte.ALERT:
            raise UnknownTypeByte()

        message, len_consumed_for_message = TlsAlertMessage.from_bytes(
            remaining_bytes)
        return TlsAlertRecord(header, message), len_consumed + len_consumed_for_message
