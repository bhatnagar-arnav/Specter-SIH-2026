# TriNetra: AI-Powered Criminal Network Analysis System

TriNetra is an end-to-end prototype designed for the SIH 2026 hackathon. It ingests raw FIR texts, extracts key entities using a deterministic NLP pipeline, and visualizes the criminal network using an interactive knowledge graph.

## Tech Stack
- **Frontend**: React.js (Vite), vis.js (Network Graph), Tailwind CSS
- **Backend**: FastAPI (Python), Pydantic
- **Database**: Neo4j
- **NLP Engine**: Python pipeline placeholder (ready for IndicBERT)

## Prerequisites
- Node.js (v18+)
- Python (3.9+)
- Neo4j Desktop or Docker container

## Setup Instructions

### 1. Database Setup (Neo4j)
You need a running instance of Neo4j. The easiest way is using Docker:
```bash
docker run \
    --name neo4j \
    -p7474:7474 -p7687:7687 \
    -d \
    -e NEO4J_AUTH=neo4j/password \
    neo4j:latest
```
*Note: Ensure the database is completely empty on startup as per the system rules.*

### 2. Backend Setup
Navigate to the `backend` directory and set up the Python environment:
```bash
cd backend
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the FastAPI server
uvicorn main:app --reload --port 8000
```

### 3. Frontend Setup
Open a new terminal, navigate to the `frontend` directory:
```bash
cd frontend

# Install dependencies
npm install

# Start the React development server
npm run dev
```

## System Rules Enforced
1. **Strict Anti-Hallucination**: The NLP pipeline uses a temperature of `0.0`. Missing entities return empty arrays `[]` rather than placeholders like "N/A".
2. **Data Sovereignty**: No external API calls are made. The system is designed to run entirely offline/on-premise.
3. **Human-in-the-Loop (HITL)**: Uploaded FIRs are presented in a split-screen view. The left pane shows the read-only raw text, and the right pane shows an editable form. Data is only committed to Neo4j after explicit user confirmation.
4. **Graph Visualization**: The graph is rendered with fixed shapes/colors for different entity types (Square for Cases, Circles for Persons, Triangles for Phones, Hexagons for Locations). Clicking on a connected FIR node seamlessly transitions the UI to that specific case.

## Usage Guide
1. Open the frontend in your browser (usually `http://localhost:5173`).
2. Click **"Upload FIR"** in the sidebar. Upload a text file (e.g., `.txt`).
3. The system will extract entities and display them in the right pane form.
4. You can edit, add, or remove extracted entities in the form.
5. Click **"Commit to Knowledge Graph"** to save the data to Neo4j.
6. The graph will render below the split-screen showing nodes and relationships.
7. Upload multiple connected FIRs to see the graph link entities across different cases. Click on a Case node to dynamically load it.
