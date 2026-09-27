from neo4j import GraphDatabase
import logging
import uuid
import os

logger = logging.getLogger(__name__)

class GraphEngine:
    """
    Neo4j and NetworkX integration for the Specter Knowledge Graph.
    """
    def __init__(self, uri=None, user=None, password=None):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "test1234")
        self.driver = None
        self._connect()

    def _connect(self):
        try:
            if not self.driver:
                self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
                self.driver.verify_connectivity()
                logger.info("Successfully connected to Neo4j database.")
                self._initialize_constraints()
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j. Error: {e}")
            self.driver = None

    def _get_session(self):
        self._connect()
        if not self.driver:
            raise Exception("Neo4j database is offline or unreachable.")
        return self.driver.session()

    def _initialize_constraints(self):
        # Enforce unique deterministic anchors in Neo4j
        queries = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (ip:IP_Address) REQUIRE ip.address IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (cw:Crypto_Wallet) REQUIRE cw.address IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (od:Onion_Domain) REQUIRE od.url IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (pk:PGP_Key) REQUIRE pk.fingerprint IS UNIQUE"
        ]
        with self._get_session() as session:
            for query in queries:
                try:
                    session.run(query)
                except Exception as e:
                    logger.warning(f"Constraint creation warning: {e}")

    def close(self):
        if self.driver:
            self.driver.close()

    def commit_verified_data(self, data: dict):
        with self._get_session() as session:
            session.execute_write(self._execute_commit_transaction, data)

    @staticmethod
    def _execute_commit_transaction(tx, data: dict):
        query = """
        MERGE (c:Intel_Report {id: $intel_id})
        SET c.summary = $summary, c.date = datetime(), c.raw_text = $raw_text, c.forensic_hash = $forensic_hash, c.ingested_at = $ingested_at

        FOREACH (actor IN $threat_actors |
            MERGE (ta:Threat_Actor {name: actor})
            MERGE (ta)-[:MENTIONED_IN]->(c)
        )

        FOREACH (ip IN $ip_addresses |
            MERGE (i:IP_Address {address: ip})
            MERGE (c)-[:LINKED_TO]->(i)
        )

        FOREACH (wallet IN $crypto_wallets |
            MERGE (cw:Crypto_Wallet {address: wallet})
            MERGE (c)-[:LINKED_TO]->(cw)
        )

        FOREACH (domain IN $onion_domains |
            MERGE (od:Onion_Domain {url: domain})
            MERGE (c)-[:LINKED_TO]->(od)
        )

        FOREACH (key IN $pgp_keys |
            MERGE (pk:PGP_Key {fingerprint: key})
            MERGE (c)-[:LINKED_TO]->(pk)
        )

        FOREACH (marker IN $linguistic_markers |
            MERGE (lm:Linguistic_Marker {marker: marker})
            FOREACH (actor IN $threat_actors |
                MERGE (ta:Threat_Actor {name: actor})
                MERGE (ta)-[:USED_SLANG]->(lm)
            )
        )
        """
        tx.run(
            query,
            intel_id=data.get("intel_id", str(uuid.uuid4())),
            raw_text=data.get("raw_text", ""),
            summary=data.get("case_summary", ""),
            threat_actors=data.get("threat_actors", []),
            ip_addresses=data.get("ip_addresses", []),
            crypto_wallets=data.get("crypto_wallets", []),
            onion_domains=data.get("onion_domains", []),
            pgp_keys=data.get("pgp_keys", []),
            linguistic_markers=data.get("linguistic_markers", []),
            forensic_hash=data.get("forensic_hash", ""),
            ingested_at=data.get("ingested_at", "")
        )

    def delete_case(self, case_id: str):
        with self._get_session() as session:
            session.run("MATCH (c:Intel_Report {id: $case_id}) DETACH DELETE c", case_id=case_id)
            session.run("MATCH (n) WHERE NOT (n)--() DELETE n")

    def generate_analytics(self):
        from analytics_engine import GraphAnalyticsEngine
        
        neo4j_records = []
        with self._get_session() as session:
            result = session.run("""
                MATCH (n)-[r]->(m) 
                RETURN id(n) as source_id, labels(n)[0] as source_label, n.name as source_name, n.address as source_address, n.url as source_url, n.fingerprint as source_fingerprint, n.id as source_uuid, n.marker as source_marker,
                       id(m) as target_id, labels(m)[0] as target_label, m.name as target_name, m.address as target_address, m.url as target_url, m.fingerprint as target_fingerprint, m.id as target_uuid, m.marker as target_marker,
                       type(r) as rel_type
            """)
            
            for record in result:
                neo4j_records.append(dict(record))

        analytics_engine = GraphAnalyticsEngine()
        return analytics_engine.generate_react_payload(neo4j_records)
