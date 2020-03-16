from typing import Tuple

from tls_parser.alert_protocol import TlsAlertRecord
from tls_parser.exceptions import UnknownTypeByte
from tls_parser.handshake_protocol import TlsHandshakeRecord
from tls_parser.record_protocol import TlsRecord
from tls_parser.record_protocol import TlsRecordHeader
from tls_parser.record_protocol import TlsRecordTypeByte


class TlsRecordParser(object):

    @staticmethod
    def parse_bytes(raw_bytes: bytes) -> Tuple[TlsRecord, int]:
        record_header, len_consumed = TlsRecordHeader.from_bytes(raw_bytes)

        # Try to parse the record
        if record_header.type == TlsRecordTypeByte.HANDSHAKE:
            return TlsHandshakeRecord.from_bytes(raw_bytes)
        if record_header.type == TlsRecordTypeByte.ALERT:
            return TlsAlertRecord.from_bytes(raw_bytes)
        if record_header.type in TlsRecordTypeByte:
            # Valid record type but we don't have the code to parse it right now
            return TlsRecord.from_bytes(raw_bytes)
        # Unknown type
        raise UnknownTypeByte()
