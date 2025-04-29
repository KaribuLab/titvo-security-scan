from dataclasses import dataclass


@dataclass
class Hint:
    id: str
    name: str
    slug: str
    url: str
    hint: str
