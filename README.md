<div align="center">
  
# SPECTER
**Evidence-Driven Threat Intelligence & Correlation Platform**

[![Status](https://img.shields.io/badge/Status-Air_Gapped_MVP-success.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](#)
[![React](https://img.shields.io/badge/React-Next.js-cyan.svg)](#)
[![Neo4j](https://img.shields.io/badge/Neo4j-Graph_DB-green.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-gray.svg)](#)

*Engineered for Smart India Hackathon 2026 (Problem Statement: SIH26151 — Dark Web De-anonymization).*

</div>

Specter is an air-gapped, AI-driven forensic intelligence platform engineered to pierce the veil of anonymity across Tor and I2P networks. Rather than simply monitoring for compromised data, Specter mathematically links anonymous dark web aliases to real-world infrastructure and clear-web footprints by exploiting operational security (OPSEC) failures, cryptocurrency flows, and linguistic fingerprints.

---

## 📸 Platform Interface & Graph Topography

> **<img width="1920" height="971" alt="Screenshot 2026-09-28 001719" src="https://github.com/user-attachments/assets/98b1e77f-111d-466e-8b8f-c4f06c240e05" />**

> *Role-based authentication terminal configured for air-gapped environments with mandatory access audit logging.*

> **<img width="1920" height="980" alt="Screenshot 2026-09-28 001711" src="https://github.com/user-attachments/assets/fc6379a2-146f-4533-bb2a-1885efae063f" />**

> *Caption: The Specter air-gapped analyst terminal during active threat ingestion.*

> **<img width="1920" height="968" alt="Screenshot 2026-09-28 001702" src="https://github.com/user-attachments/assets/6f384b6e-dbe3-475a-b5ca-8a9c52f1ea0c" />**
> *Caption: .Intercept Upload & NLP Trigger — Ingestion interface allowing direct loading of unformatted forensic intercepts (.txt) for local, offline transformer processing.*
> **<img width="1920" height="968" alt="Screenshot 2026-09-28 001650" src="https://github.com/user-attachments/assets/44a29f3b-03e3-4187-b318-0a0662b51ea2" />**

> *Caption: Automated Entity Extraction & Forensic Hashing — Simultaneous execution of IndicBERT and regex extraction against raw intercepts, generating immutable SHA-256 integrity checksums and ISO-8601 timestamps alongside structured entity parsing.*

---

## 🧠 Core Architecture & Workflow

Specter is built specifically for defense-sector operational security. It operates as the "Intelligence Brain" sitting securely behind an agency's data harvesters.

1. **Ingestion:** Analysts feed raw, unstructured intercepts (forum dumps, Telegram chats, hidden service logs) into the isolated terminal.
2. **AI Extraction:** A locally cached HuggingFace IndicBERT model, fused with a fault-tolerant regex pipeline, extracts high-value cyber-artifacts: BTC/XMR/ETH wallets, IPv4 addresses, `.onion` URLs, PGP fingerprints, and threat actor aliases.
3. **Graph Mapping:** Extracted entities are instantly mapped into a **Neo4j** graph database, dynamically forming `TRANSACTED_WITH`, `USED_SLANG`, and `COMMUNICATED_ON` relationships.
4. **Nexus Detection:** The **NetworkX** analytics engine continuously calculates the Betweenness Centrality of the network to isolate the structural linchpin connecting isolated criminal cells.

---

## ✨ Key Features

*   **Linguistic Fingerprinting (Stylometry):** Profiles threat actors by behavioral writing habits. If disparate aliases share a rare combination of regional slang or hacker jargon, the graph mathematically links them as a single human operator.
*   **Betweenness Centrality Nexus Detection:** Specter does not just map data; it calculates the mastermind. The system automatically highlights the "Red Dot" (Nexus)—the critical IP address, intermediary wallet, or hidden broker keeping the operation alive.
*   **Forensic Chain of Custody:** Every raw intelligence intercept is stamped with a SHA-256 cryptographic checksum and UTC ISO-8601 timestamp upon ingestion to ensure data integrity and legal defensibility.
*   **STIX 2.1 Interoperability:** Analysts can export the live de-anonymization graph into a globally standardized STIX-compliant JSON bundle, ready for immediate integration with enterprise SIEMs (e.g., Splunk) and national CERT grids.

---

## 🏗️ Tech Stack

### Backend & Analytics
*   **FastAPI (Python):** High-throughput asynchronous API routing.
*   **Neo4j:** Multi-relational graph database mapping deep intelligence networks.
*   **NetworkX:** Complex graph theory mathematics for centrality calculations.
*   **IndicBERT & Custom CTI Regex:** High-recall Named Entity Recognition (NER) on non-standard hacker vernacular.

### Frontend Interface
*   **React & Next.js:** Fast, component-driven UI architecture.
*   **Tailwind CSS:** Clean, dark-mode-first styling for extended analyst sessions.
*   **vis.js:** Interactive, physics-based node topography for network visualization.

### Infrastructure
*   **Docker & Docker Compose:** 100% containerized deployment (`specter_airgap_net`) ensuring offline viability.

---

## 🚀 Quick Start (Air-Gapped Deployment)

Specter is designed to run completely offline on closed networks. Ensure you have **Docker** and **Docker Compose** installed on your host machine.

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/bhatnagar-arnav/Specter-SIH-2026.git](https://github.com/bhatnagar-arnav/Specter-SIH-2026.git)
   cd Specter-SIH-2026

2.Spin up the isolated stack:

Bash
docker-compose up --build -d
Note: On the initial build, the backend container will download the IndicBERT NLP weights. Once cached in the container volume, the system can run indefinitely without external internet access.

3.Access the Analyst Terminal:
Open your browser and navigate to:

Plaintext
http://localhost:3000

🏆 About the Project
Specter was conceptualized and developed by Team Aletheia. The prototype secured a winning position among 50 competing teams at the internal UPES Smart India Hackathon qualifiers , advancing to represent the university for SIH26151.






