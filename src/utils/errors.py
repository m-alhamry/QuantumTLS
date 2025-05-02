import logging
from src.utils.utils import ALERT_DESCRIPTIONS

class TLSError(Exception):
    """
    Custom exception class for TLS-related errors, aligned with TLS 1.3 alert handling (RFC 8446, Section 6).

    Attributes:
        alert_type (int): TLS alert type code (e.g., ALERT_HANDSHAKE_FAILURE).
        description (str): Human-readable alert description from ALERT_DESCRIPTIONS.
    """

    def __init__(self, message: str, alert_type: int, logger: logging.Logger = None, network=None):
        """
        Initialize the TLSError instance.

        Args:
            message (str): Detailed error message.
            alert_type (int): TLS alert type code from utils.ALERT_* constants.
            logger (logging.Logger, optional): Logger for error logging.
            network (optional): Network object to send the alert.

        Notes:
            - Logs the error with the alert description and type.
            - Sends the alert via the network if provided and possible.
        """
        super().__init__(message)
        self.alert_type = alert_type
        self.description = ALERT_DESCRIPTIONS.get(alert_type, "Unknown")
        
        # Log the error if a logger is provided
        if logger:
            logger.error(f"TLSError: {message} (Alert: {self.description}, {alert_type:02x})")
        
        # Send the alert via the network if available
        if network:
            try:
                network.send_alert(alert_type, message, encrypt=(network.crypto and not network.crypto.is_handshake_phase))
            except Exception as e:
                if logger:
                    logger.warning(f"Failed to send alert '{self.description}': {e}")