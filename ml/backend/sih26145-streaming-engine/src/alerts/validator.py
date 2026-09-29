from src.alerts.schema import AlertSchema


class AlertValidator:
    """
    Validates AlertSchema objects against schema rules and parameter bounds.
    """

    VALID_SEVERITIES = {"low", "medium", "high", "critical"}

    def validate(self, alert: AlertSchema) -> bool:
        if not alert.id or not isinstance(alert.id, str):
            raise ValueError("Alert ID must be a non-empty string")

        if alert.confidence < 0.0 or alert.confidence > 1.0:
            raise ValueError(f"Confidence {alert.confidence} out of range [0.0, 1.0]")

        if alert.severity.lower() not in self.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{alert.severity}'. Must be one of {self.VALID_SEVERITIES}")

        if not alert.threat_type:
            raise ValueError("Threat class must not be empty")

        if not alert.src_ip:
            raise ValueError("Source IP must not be empty")

        return True
