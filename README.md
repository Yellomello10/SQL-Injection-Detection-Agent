# 🔍 Gemini SQL Injection Detection & Classification Agents

An AI-powered SQL injection vulnerability scanner built with **Python** and the **Gemini API** (`gemini-2.5-flash`). The project operates entirely offline by default (using a local SQLite-backed target REST API) and features two specialized AI agents that coordinate to find and analyze SQL injection vulnerabilities.

> ⚠️ **SECURITY DISCLAIMER**: This project is for **authorized security research and education only**. The target API is intentionally vulnerable. **Never deploy the target API on any public or production system.** Only run the scanner against systems you own or have explicit written permission to test.

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Gemini SQL Injection Agents                     │
│                                                                        │
│   ┌────────────────────────┐              ┌────────────────────────┐   │
│   │    Detection Agent     │◄───HTTPS────►│       Gemini API       │   │
│   │   (gemini_agents.py)   │              │   (gemini-2.5-flash)   │   │
│   └───────────┬────────────┘              └───────────▲────────────┘   │
│               │                                       │                │
│             HTTP                                    HTTPS              │
│               ▼                                       │                │
│   ┌────────────────────────┐              ┌───────────▼────────────┐   │
│   │    Target Flask API    │              │    Classifier Agent    │   │
│   │    (app_sqlite.py)     │              │   (gemini_agents.py)   │   │
│   └───────────┬────────────┘              └───────────┬────────────┘   │
│               │                                       │                │
│            SQLite                                  Renders             │
│               ▼                                       ▼                │
│   ┌────────────────────────┐              ┌────────────────────────┐   │
│   │      sqli_test.db      │              │        Reporter        │   │
│   │     (Local SQLite)     │              │   • JSON & HTML report │   │
│   └────────────────────────┘              │   • Rich terminal table│   │
│                                           └────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

The scan logic employs a two-agent architecture:
1. **Detection Agent**: Autonomously crawls the target API, probes parameters with SQL injection payloads, compares responses against baselines, and uses Gemini to verify if the differences confirm a vulnerability.
2. **Classifier Agent**: Takes the confirmed vulnerability context and details to identify the exact SQLi subtype (e.g. Union-based, Error-based, Stacked Queries, Blind, Time-based), calculate a CVSS score, set severity, and output customized remediation.

---

## 🚀 Quickstart (3 Commands)

### Prerequisites
- Python 3.11+
- A [Gemini API Key](https://ai.google.dev/)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure your API key in .env
cp .env.example .env
# Open .env and set: GEMINI_API_KEY=your_actual_key_here

# 3. Run the scanner!
python run_gemini_scan.py --fast --verbose
```

Reports are automatically saved to `./reports/` as both `<scan_id>.json` and `<scan_id>.html`.

---

## 📂 Project Structure

```
sql_injection_agent/
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variables template
├── run_gemini_scan.py          # Main launcher script (starts server + runs agents)
│
├── target_api/                 # ⚠️ Intentionally vulnerable target REST API
│   ├── app_sqlite.py           # SQLite-backed Flask web server (no Docker needed!)
│   └── sqli_test.db            # Local seed database
│
├── agent/                      # 🤖 AI detection & classification agents
│   ├── gemini_agents.py        # Gemini Client, Detection & Classifier agents
│   ├── tools.py                # Scanner tools (probe, inject, baseline analysis)
│   ├── payloads.py             # 57 SQLi payload library (7 categories)
│   └── reporter.py             # JSON, HTML, and Rich terminal output reporter
│
└── tests/                      # 🧪 Test suite
    └── test_agent.py           # Pytest unit tests verifying scanner tools
```

---

## 🔌 Vulnerable API Endpoints

The target server implements 6 vulnerable endpoints and 1 safe endpoint to test the agents' sensitivity:

| Method | Endpoint | Parameter | Target Vulnerability Subtype |
|--------|----------|-----------|------------------------------|
| GET | `/api/users` | `id` | Classic Error-Based SQLi |
| GET | `/api/products` | `category` | UNION-Based SQLi |
| POST | `/api/login` | `username`, `password` | Authentication Bypass |
| GET | `/api/orders` | `user_id`, `status` | Blind Boolean SQLi |
| GET | `/api/search` | `q` | Time-Based Blind SQLi |
| GET | `/api/admin/users` | `role` | Stacked Queries SQLi |
| GET | `/api/reports` | `from`, `to` | ✅ **SAFE** (parameterized control) |
| GET | `/health` | — | Target API status |

---

## 🧪 Running Tests

Verify the core scanner tool logic using Pytest (no API key required):
```bash
pytest tests/ -v -m "not integration"
```

---

## ⚙️ Configuration Options

All settings are controlled via environment variables in the `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | *(required)* | Your Google Gemini API Key |
| `TARGET_API_BASE_URL` | `http://localhost:5000` | Base URL of the target API |
| `REPORT_OUTPUT_DIR` | `./reports` | Output directory for HTML + JSON reports |
| `TIME_BASED_THRESHOLD` | `3.0` | Response delay threshold in seconds |
| `LOG_LEVEL` | `INFO` | Console logging verbosity |

---

## 🛡️ Payload Library (57 payloads)

- **`CLASSIC_ERROR_BASED` (10)**: Provokes SQL syntax errors to detect vulnerability.
- **`UNION_BASED` (8)**: Appends `UNION SELECT` to retrieve schema/rows.
- **`BLIND_BOOLEAN` (10)**: Infers structure based on true/false response differences.
- **`TIME_BASED` (8)**: Uses side-channel `SLEEP()` injections to trigger latency checks.
- **`AUTH_BYPASS` (10)**: Bypasses authentication checks.
- **`STACKED_QUERIES` (6)**: Appends multiple SQL statements separated by semicolons.
- **`SECOND_ORDER` (5)**: Payloads designed to execute upon secondary retrieval.
