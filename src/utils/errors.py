"""Protocol errors have no I/O side effects; connection owners handle alerts once."""
from src.utils.utils import ALERT_DESCRIPTIONS


class TLSError(Exception):
    def __init__(self, message, alert_type, logger=None, network=None):
        super().__init__(message)
        self.alert_type = alert_type
        self.description = ALERT_DESCRIPTIONS.get(alert_type, 'unknown')
