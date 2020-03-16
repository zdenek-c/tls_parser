from tls_parser.record_protocol import TlsRecord
from tls_parser.record_protocol import TlsRecordHeader
from tls_parser.record_protocol import TlsRecordTypeByte
from tls_parser.record_protocol import TlsSubprotocolMessage
from tls_parser.tls_version import TlsVersionEnum


class TlsApplicationDataMessage(TlsSubprotocolMessage):

    def __init__(self, application_data: bytes) -> None:
        self.data = application_data

    def to_bytes(self) -> bytes:
        return self.data


class TlsApplicationDataRecord(TlsRecord):
    """We make the assumption that an Application record only contains one message, which seems to be the case in the
    real world.
    """

    def __init__(
            self,
            record_header: TlsRecordHeader,
            application_data: TlsApplicationDataMessage) -> None:
        super(TlsApplicationDataRecord, self).__init__(
            record_header, [application_data])

    @classmethod
    def from_parameters(
            cls,
            tls_version: TlsVersionEnum,
            application_data: bytes) -> "TlsApplicationDataRecord":
        message = TlsApplicationDataMessage(application_data)
        record_header = TlsRecordHeader(
            TlsRecordTypeByte.APPLICATION_DATA, tls_version, message.size)
        return TlsApplicationDataRecord(record_header, message)
