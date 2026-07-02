from dataclasses import dataclass


@dataclass
class EntityRegisteredEventDetails:

    schema: int

    source: str

    method: str

    fingerprint: str