from pydantic import BaseModel, Field
from typing import List

class IntelExtraction(BaseModel):
    case_summary: str = Field(default="")
    threat_actors: List[str] = Field(default_factory=list)
    ip_addresses: List[str] = Field(default_factory=list)
    crypto_wallets: List[str] = Field(default_factory=list)
    onion_domains: List[str] = Field(default_factory=list)
    pgp_keys: List[str] = Field(default_factory=list)
    linguistic_markers: List[str] = Field(default_factory=list)
    forensic_hash: str = ""
    ingested_at: str = ""

class IntelCommitRequest(BaseModel):
    intel_id: str = ""
    raw_text: str = ""
    case_summary: str = ""
    threat_actors: List[str] = Field(default_factory=list)
    ip_addresses: List[str] = Field(default_factory=list)
    crypto_wallets: List[str] = Field(default_factory=list)
    onion_domains: List[str] = Field(default_factory=list)
    pgp_keys: List[str] = Field(default_factory=list)
    linguistic_markers: List[str] = Field(default_factory=list)
    forensic_hash: str = ""
    ingested_at: str = ""
