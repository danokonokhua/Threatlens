# ThreatLens — Cyber Threat Intelligence & SOC Operations Platform

[![CI/CD Quality Gates](https://github.com/danokonokhua/Threatlens/actions/workflows/test.yml/badge.svg)](https://github.com/danokonokhua/Threatlens/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11+-3776ab.svg)](https://www.python.org/)
[![Next.js: 16](https://img.shields.io/badge/Next.js-16-black.svg)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-009688.svg)](https://fastapi.tiangolo.com/)
[![OASIS STIX 2.1](https://img.shields.io/badge/OASIS-STIX%202.1-red.svg)](https://oasis-open.github.io/cti-documentation/)

An enterprise-grade Cyber Threat Intelligence (CTI) and Security Operations Centre (SOC) platform for aggregating, correlating, scoring, and operationalising threat intelligence across the incident lifecycle.

Built according to the **Sentinova Security Systems ThreatLens PRD (v1.0)** specifications.

---

## 🚀 Key Platform Capabilities

### 1. Multi-Source Threat Feed Ingestion (FR-01, FR-05)
Aggregates and normalises indicators across **7 independent intelligence sources** with deduplication and source provenance tracking:
- **URLhaus** (abuse.ch) — Malicious distribution URLs
- **Feodo Tracker** (abuse.ch) — Botnet C2 IP addresses
- **MalwareBazaar** (abuse.ch) — Fresh malware payload SHA-256 hashes
- **ThreatFox** (abuse.ch) — Multi-type IOCs linked to adversary campaigns
- **CISA KEV Catalog** — Actively exploited vulnerabilities and zero-days
- **AlienVault OTX** — Community-curated threat intelligence pulses
- **OpenPhish** — Zero-hour verified phishing URLs

### 2. Deterministic Scoring Engine (FR-13)
Transparent, reproducible severity rating from 0 to 100:
$$\text{Score} = (\text{Base} \times 0.4) + (\text{Confidence} \times 0.3) + (\text{Recency} \times 0.2) + (\text{MultiSource} \times 0.1)$$
- **30-day linear recency decay** (stale indicators naturally age out)
- **Multi-source corroboration boost** (capped at 5 distinct sources)
- **Redis caching** for sub-millisecond enrichment lookups

### 3. Purpose-Built Role-Based Dashboards (Section 12)
Tailored operational interfaces mapped to the escalation chain:
- **🛡️ Executive Overview (Rachel Adeyemi, CISO)**: 30-day exposure trajectory, headline risk score, 7-day SOC throughput (ingested vs. resolved), and board briefing.
- **⚡ SOC Analyst Dashboard (Priya Nair, Tier-2 Analyst)**: Real-time WebSocket alert stream (`/ws/alerts`), live queue, feed pipeline controls, and interactive distribution charts.
- **📁 Incident Response Workspace (Daniel Okafor, IR Lead)**: Investigation workspace, correlated alerts list, interactive containment checklist, and **append-only chronological audit timeline (FR-19)**.
- **🎯 Threat Hunting Engine (Mei Lin Tan, Hunter)**: Sub-second faceted full-text search (**FR-25**, instrumented `latency_ms` < 800ms), MITRE ATT&CK technique pivots, and proactive hunt rule execution runner.

### 4. Global Attack Heatmap (FR-20)
- Equirectangular vector world map shading threat origin density.
- Pulsing SVG heat nodes with critical severity auras.
- Interactive hover HUD inspection (country volume, critical breakdown, top observed threat vector).
- Top threat origins leaderboard.

### 5. Interoperability & Export Standards (FR-23, FR-24)
- **OASIS STIX 2.1 Bundle Export** (`/api/v1/export/stix`): Directly consumable by Splunk, Sentinel, QRadar, Cortex XSOAR, and MISP.
- **Perimeter CSV Feed** (`/api/v1/export/csv`): Formatted for perimeter edge firewalls and proxy blocklists.
- **On-Demand Intelligence Reports** (`/api/v1/reports`): Board-ready executive briefings with one-click print/PDF export.

---

## 🏛️ System Architecture

```
                  ┌────────────────────────────────────────────────────────┐
                  │              PRESENTATION LAYER (Next.js 16)           │
                  │   Executive · SOC Analyst · Incident Response · Hunter │
                  └───────────────▲────────────────────────▲───────────────┘
                                  │ REST API               │ WebSocket
                  ┌───────────────▼────────────────────────┴───────────────┐
                  │             API & GATEWAY LAYER (FastAPI)              │
                  │       JWT Auth · RBAC (6 Roles) · Immutable Audit Log   │
                  └───────────────▲────────────────────────▲───────────────┘
                                  │                        │
       ┌──────────────────────────┴───────────────┐        │
       │       INTELLIGENCE & DATA LAYER          │        │ Task Queue
       │  PostgreSQL (System of Record)           │        │
       │  Elasticsearch (Faceted Search Index)    │        ▼
       │  Redis (Cache & Event Pub/Sub Bus)       │  ┌──────────────────────┐
       └──────────────────────────────────────────┘  │ 7 Threat Feed Parsers│
                                                     └──────────────────────┘
```

---

## 🛠️ Technology Stack

| Layer | Technology |
| :--- | :--- |
| **Frontend** | Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS, Recharts, Lucide Icons |
| **Backend** | Python 3.11, FastAPI, SQLAlchemy 2 (Async), Pydantic v2, Uvicorn |
| **State & Search** | PostgreSQL 15, Elasticsearch 8.11, Redis 7 (Pub/Sub & Caching) |
| **Real-time** | Native FastAPI WebSockets + Redis Pub/Sub event bus |
| **Testing** | Pytest, pytest-asyncio, pytest-cov, TypeScript compiler |
| **Standards** | OASIS STIX 2.1, MITRE ATT&CK, Traffic Light Protocol (TLP) |

---

## ⚡ Quickstart

### 1. Prerequisites
- [Docker](https://www.docker.com/) & Docker Compose
- [Git](https://git-scm.com/)

### 2. Clone & Launch
```bash
git clone https://github.com/danokonokhua/Threatlens.git
cd Threatlens

# Start all microservices (Postgres, Redis, Elasticsearch, Backend, Frontend)
docker compose up -d
```

### 3. Access Surfaces
- **Interactive SOC Dashboard**: [http://localhost:3000](http://localhost:3000)
- **FastAPI Interactive Docs (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **API Health Endpoint**: [http://localhost:8000/health](http://localhost:8000/health)

---

## 🧪 Testing & Quality Gates

The test suite validates deterministic scoring, feed normalization, STIX 2.1 formatting, and RBAC:

```bash
# Run backend test suite with coverage gate (NFR-08: >= 80% coverage)
cd backend
pytest tests/ -v --cov=app/services/scoring --cov=app/feeds --cov=app/auth --cov-fail-under=80

# Run frontend type-safety verification
cd ../frontend
npx tsc --noEmit
```

---

## 📄 License
This project is licensed under the MIT License.
