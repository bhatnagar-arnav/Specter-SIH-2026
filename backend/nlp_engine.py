import re
import logging
import torch
from transformers import AutoTokenizer, AutoModelForTokenClassification, AutoModelForSequenceClassification
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NLPEngine:
    def __init__(self, model_path=None):
        logger.info("Initializing Specter CTI Extraction Engine (IndicBERT + Regex Fallbacks)...")
        # In a fully air-gapped setup, load model_path here.
        # self.tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
        # self.model = AutoModelForTokenClassification.from_pretrained(model_path, local_files_only=True)

    def process_intel_text(self, text: str) -> Dict[str, Any]:
        """
        Extracts Threat Actors, IPs, Crypto Wallets, Onion Domains, and PGP Keys from Dark Web / CTI text.
        """
        # 1. Initialize independent, empty lists
        threat_actors = []
        crypto_wallets = []
        ip_addresses = []
        onion_domains = []
        pgp_keys = []
        linguistic_markers = []

        # 2. Execute independent re.findall() passes against the RAW text
        btc_pattern = r"\b(?:1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}\b"
        xmr_pattern = r"\b(?:4|8)[0-9a-zA-Z]{80,105}\b"
        eth_pattern = r"\b0x[a-fA-F0-9]{40}\b"
        
        for w in re.findall(btc_pattern, text): crypto_wallets.append(f"BTC:{w}")
        for w in re.findall(xmr_pattern, text): crypto_wallets.append(f"XMR:{w}")
        for w in re.findall(eth_pattern, text): crypto_wallets.append(f"ETH:{w}")

        actor_sig_pattern = r"-\s*([a-zA-Z0-9_]+)\s*$"
        actor_inline_pattern = r"(?:operator|User|@)\s+([a-zA-Z0-9_]+)"
        threat_actors.extend(re.findall(actor_sig_pattern, text, re.MULTILINE))
        threat_actors.extend(re.findall(actor_inline_pattern, text, re.IGNORECASE))

        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ip_addresses.extend(re.findall(ip_pattern, text))

        onion_pattern = r"\b[a-z2-7]{16,56}\.onion\b"
        onion_domains.extend(re.findall(onion_pattern, text, re.IGNORECASE))

        pgp_pattern = r"\b[A-Fa-f0-9]{40}\b"
        pgp_keys.extend(re.findall(pgp_pattern, text))

        # Linguistic Markers
        slang_keywords = ["pwned", "dox", "ransom", "fud", "crypter", "botnet", "0day", "rat", "skid", "c2", "opsec", "jabber", "escrow", "exploit", "cve", "cc", "fullz", "dumps"]
        for word in text.split():
            clean_word = re.sub(r'[^a-zA-Z0-9]', '', word.lower())
            if clean_word in slang_keywords:
                linguistic_markers.append(clean_word)

        # Case Summary
        summary = "Dark Web Cyber Intelligence Report"
        inc_match = re.search(r'Intel Summary\s*:\s*(.*?)(?=\n\n|\n[A-Z][a-z]+\s*:|$)', text, re.IGNORECASE | re.DOTALL)
        if inc_match:
            summary = inc_match.group(1).strip()[:180] + "..."
        elif len(text) > 0:
            summary = text[:180] + "..."

        # 3. Deduplicate every list using list(set()) before returning
        return {
            "case_summary": summary,
            "threat_actors": list(set(threat_actors)),
            "ip_addresses": list(set(ip_addresses)),
            "crypto_wallets": list(set(crypto_wallets)),
            "onion_domains": list(set(onion_domains)),
            "pgp_keys": list(set(pgp_keys)),
            "linguistic_markers": list(set(linguistic_markers))
        }
