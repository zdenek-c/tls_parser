from typing import Tuple

from tls_parser.record_protocol import TlsRecord
from tls_parser.record_protocol import TlsRecordHeader
from tls_parser.record_protocol import TlsRecordTypeByte
from tls_parser.record_protocol import TlsSubprotocolMessage
from tls_parser.tls_version import TlsVersionEnum


class TlsChangeCipherSpecRecord(TlsRecord):

    @classmethod
    def from_parameters(cls, tls_version: TlsVersionEnum) -> "TlsChangeCipherSpecRecord":
        ccs_message = TlsSubprotocolMessage(b"\x01")
        record_header = TlsRecordHeader(
            TlsRecordTypeByte.CHANGE_CIPHER_SPEC, tls_version, ccs_message.size)
        return TlsChangeCipherSpecRecord(record_header, [ccs_message])

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> Tuple["TlsChangeCipherSpecRecord", int]:
        raise NotImplementedError()
