import logging
from utils import ALERT_DESCRIPTIONS

class TLSError(Exception):
    """
    Custom exception class for TLS-related errors, aligned with TLS 1.3 alert handling.

    Attributes:
        alert_type: TLS alert type code (e.g., ALERT_HANDSHAKE_FAILURE).
        description: Human-readable alert description from ALERT_DESCRIPTIONS.
    """

    def __init__(self, message: str, alert_type: int, logger: logging.Logger = None, network=None):
        """
        Initialize the TLSError instance.

        Args:
            message: Detailed error message.
            alert_type: TLS alert type code.
            logger: Optional logger for error logging.
            network: Optional network object to send the alert.
        """
        super().__init__(message)
        self.alert_type = alert_type
        self.description = ALERT_DESCRIPTIONS.get(alert_type, "Unknown")
        if logger:
            logger.info(f"TLSError: {message} (Alert: {self.description}, {alert_type:02x})")
        if network:
            try:
                network.send_alert(alert_type, message)
            except Exception as e:
                if logger:
                    logger.warning(f"Failed to send alert: {e}")