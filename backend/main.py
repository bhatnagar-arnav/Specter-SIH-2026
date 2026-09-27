from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import logging
import hashlib
from datetime import datetime, timezone
from nlp_engine import NLPEngine
from graph_engine import GraphEngine
from fastapi.middleware.cors import CORSMiddleware
from schema import IntelCommitRequest

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Specter Backend API", description="Dark Web Threat Actor De-anonymization System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize singletons
try:
    nlp = NLPEngine(model_path="ai4bharat/indic-bert")
except Exception as e:
    logger.warning(f"Failed to initialize NLP engine. Error: {e}")
    nlp = None

graph_db = GraphEngine()

class IntelInput(BaseModel):
    text: str
    analyst_id: str = "UNKNOWN"

class ExtractionResponse(BaseModel):
    case_summary: str
    threat_actors: List[str] = []
    ip_addresses: List[str] = []
    crypto_wallets: List[str] = []
    onion_domains: List[str] = []
    pgp_keys: List[str] = []
    linguistic_markers: List[str] = []
    forensic_hash: str = ""
    ingested_at: str = ""

@app.post("/api/ingest-intel", response_model=ExtractionResponse)
async def ingest_intel(request: IntelInput):
    try:
        intel_text = request.text
        if not intel_text:
            raise HTTPException(status_code=400, detail="No text provided")
        
        if not nlp:
            raise HTTPException(status_code=500, detail="NLP Engine offline.")
            
        extracted_data = nlp.process_intel_text(intel_text)
        
        # Forensic Hashing (Phase 1)
        forensic_hash = hashlib.sha256(intel_text.encode('utf-8')).hexdigest()
        ingested_at = datetime.now(timezone.utc).isoformat()
        
        extracted_data["forensic_hash"] = forensic_hash
        extracted_data["ingested_at"] = ingested_at
        
        return extracted_data
    except Exception as e:
        logger.error(f"Extraction Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/intel-reports")
async def get_committed_intel():
    try:
        reports = []
        with graph_db._get_session() as session:
            result = session.run("MATCH (c:Intel_Report) RETURN c.id as intel_id")
            for record in result:
                if record["intel_id"]:
                    reports.append(record["intel_id"])
        return {"reports": reports}
    except Exception as e:
        logger.error(f"Failed to fetch intel reports: {e}")
        return {"reports": []}

@app.post("/api/commit-intel")
async def commit_intel(payload: IntelCommitRequest):
    data = {
        "intel_id": payload.intel_id,
        "raw_text": payload.raw_text,
        "case_summary": payload.case_summary,
        "threat_actors": payload.threat_actors,
        "ip_addresses": payload.ip_addresses,
        "crypto_wallets": payload.crypto_wallets,
        "onion_domains": payload.onion_domains,
        "pgp_keys": payload.pgp_keys,
        "linguistic_markers": payload.linguistic_markers,
        "forensic_hash": payload.forensic_hash,
        "ingested_at": payload.ingested_at
    }
        
    try:
        graph_db.commit_verified_data(data)
        return {"status": "success", "message": "Verified data committed to Knowledge Graph."}
    except Exception as e:
        logger.error(f"Graph commit failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/analytics")
async def get_graph_analytics():
    try:
        analytics = graph_db.generate_analytics()
        return analytics
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/intel/{intel_id}")
async def delete_intel(intel_id: str):
    try:
        graph_db.delete_case(intel_id)
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Failed to delete report {intel_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/intel-report/{intel_id}")
async def get_intel_details(intel_id: str):
    query = """
    MATCH (c:Intel_Report {id: $intel_id})
    OPTIONAL MATCH (ta:Threat_Actor)-[:MENTIONED_IN]->(c)
    OPTIONAL MATCH (ta)-[:USED_SLANG]->(lm:Linguistic_Marker)
    OPTIONAL MATCH (c)-[:LINKED_TO]->(ip:IP_Address)
    OPTIONAL MATCH (c)-[:LINKED_TO]->(cw:Crypto_Wallet)
    OPTIONAL MATCH (c)-[:LINKED_TO]->(od:Onion_Domain)
    OPTIONAL MATCH (c)-[:LINKED_TO]->(pk:PGP_Key)
    RETURN c.id AS intel_id, c.summary AS case_summary, c.raw_text AS raw_text,
           c.forensic_hash AS forensic_hash, c.ingested_at AS ingested_at,
           collect(DISTINCT ta.name) AS actors,
           collect(DISTINCT lm.marker) AS markers,
           collect(DISTINCT ip.address) AS ips,
           collect(DISTINCT cw.address) AS wallets,
           collect(DISTINCT od.url) AS domains,
           collect(DISTINCT pk.fingerprint) AS pgp_keys
    """
    try:
        with graph_db._get_session() as session:
            result = session.run(query, intel_id=intel_id)
            record = result.single()
            if not record or not record["intel_id"]:
                raise HTTPException(status_code=404, detail="Report not found")
            return {
                "intel_id": record["intel_id"],
                "raw_text": record["raw_text"] or "Raw text not available.",
                "case_summary": record["case_summary"] or "",
                "forensic_hash": record["forensic_hash"] or "",
                "ingested_at": record["ingested_at"] or "",
                "threat_actors": [a for a in record["actors"] if a],
                "linguistic_markers": [m for m in record["markers"] if m],
                "ip_addresses": [ip for ip in record["ips"] if ip],
                "crypto_wallets": [w for w in record["wallets"] if w],
                "onion_domains": [d for d in record["domains"] if d],
                "pgp_keys": [p for p in record["pgp_keys"] if p]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/export-stix")
async def export_stix():
    import uuid
    query = """
    MATCH (n)
    RETURN n.id AS id, labels(n)[0] AS label, n.name AS name, n.address AS address, n.url AS url, n.fingerprint AS fingerprint, n.marker AS marker, n.summary AS summary
    """
    try:
        objects = []
        with graph_db._get_session() as session:
            result = session.run(query)
            for record in result:
                label = record["label"]
                node_id = record["id"] or str(uuid.uuid4())
                
                name_val = record["name"] or record["address"] or record["url"] or record["fingerprint"] or record["marker"] or record["summary"] or "Unknown"
                
                stix_type = "indicator"
                if label == "Threat_Actor":
                    stix_type = "threat-actor"
                elif label == "Intel_Report":
                    stix_type = "report"

                stix_obj = {
                    "type": stix_type,
                    "spec_version": "2.1",
                    "id": f"{stix_type}--{node_id}",
                    "created": datetime.now(timezone.utc).isoformat(),
                    "modified": datetime.now(timezone.utc).isoformat(),
                    "name": name_val
                }

                if stix_type == "indicator":
                    stix_obj["pattern_type"] = "stix"
                    stix_obj["pattern"] = f"[{label.lower()}:value = '{name_val}']"
                    stix_obj["valid_from"] = datetime.now(timezone.utc).isoformat()
                
                objects.append(stix_obj)
                
        return {
            "type": "bundle",
            "id": f"bundle--{str(uuid.uuid4())}",
            "spec_version": "2.1",
            "objects": objects
        }
    except Exception as e:
        logger.error(f"Failed to export STIX: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/clear_database")
async def clear_database():
    query = "MATCH (n) DETACH DELETE n"
    try:
        with graph_db._get_session() as session:
            session.run(query)
        return {"status": "success", "message": "Knowledge Graph completely wiped."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
