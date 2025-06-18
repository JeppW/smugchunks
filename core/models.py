from dataclasses import dataclass

@dataclass
class Finding:
    host: str
    title: str
    req: str

