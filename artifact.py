class Artifact:
    def __init__(self, artifact_type, value, pid, offset,
                 source=None, extra=None, timestamp=None):
        self.artifact_type = artifact_type
        self.value         = value
        self.pid           = pid
        self.offset        = offset
        self.source        = source
        self.extra         = extra or {}
        self.timestamp     = timestamp

    def to_row(self):
        category   = self.extra.get("category", "")
        offset_str = hex(self.offset) if isinstance(self.offset, int) else (self.offset or "")
        return (
            self.artifact_type,
            category,
            self.value[:150],
            str(self.pid),
            offset_str,
        )