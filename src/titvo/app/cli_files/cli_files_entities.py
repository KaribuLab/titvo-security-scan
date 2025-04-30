from dataclasses import dataclass


@dataclass
class CliFiles:
    batch_id: str
    file_key: str
    ttl: int
