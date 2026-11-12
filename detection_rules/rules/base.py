class DetectionRule:
    def __init__(self, rule_id, severity, remediation):
        self.rule_id = rule_id
        self.severity = severity
        self.remediation = remediation

    def check(self, response_data):
        raise NotImplementedError("Subclasses must implement this method")
