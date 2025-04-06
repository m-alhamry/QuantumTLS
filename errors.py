import logging
from utils import ALERT_DESCRIPTIONS

class TLSError(Exception):
    """
    Custom exception for TLS-related errors and alerts in QuantumTLS.

    Attributes:
        message (str): Detailed error message.
        alert_type (int): TLS alert type code (e.g., ALERT_ILLEGAL_PARAMETER).
        description (str): Human-readable alert description.
    """
    def __init__(self, message: str, alert_type: int, logger: logging.Logger = None, network=None):
        """
        Initialize a TLSError instance.

        Args:
            message (str): Detailed error message.
            alert_type (int): Corresponding TLS alert type code.
            logger (logging.Logger, optional): Logger to record the error.
            network (optional): Network object to send the alert if provided.
        """
        super().__init__(message)
        self.alert_type = alert_type
        self.description = ALERT_DESCRIPTIONS.get(alert_type, "Unknown")
        if logger:
            logger.error(f"TLSError: {message} (Alert: {self.description}, {alert_type:02x})")
        if network:
            try:
                network.send_alert(alert_type, message)
            except Exception as e:
                if logger:
                    logger.warning(f"Failed to send alert: {e}")