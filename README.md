# TrustVault — High-Assurance Secure Document Sharing

> **"A platform where the wrong person cannot reach a document, and where you can prove exactly who reached it."**

TrustVault is an enterprise document platform built with defense-in-depth security principles. It ensures confidential documents (executive compensation, contracts, patent drawings, regulatory audit papers) are protected by strict server-side authorization, encryption at rest, immediate revocation, and a mathematically verifiable cryptographic audit trail.

---

## Evaluation Credentials (Pre-Seeded)

The database automatically seeds with 4 test accounts representing all roles:

| Role | Name & Title | Email | Password | Permissions & Scope |
| :--- | :--- | :--- | :--- | :--- |
| **Administrator** | Eleanor Vance (CSO) | `admin@trustvault.internal` | `AdminPass123!@#` | Full audit trail inspection, user management, session killing |
| **Document Owner** | Alice Wright (Head of Ops) | `alice@trustvault.internal` | `OwnerPass123!@#` | Uploads files, grants access, revokes access, manages permissions |
| **Internal Viewer** | Bob Jenkins (Analyst) | `bob@trustvault.internal` | `ViewerPass123!@#` | Read-only access to granted contracts; strictly forbidden from unshared salary review |
| **External Counsel** | Charlie Zhang (Legal) | `charlie@client.corp` | `PartnerPass123!@#` | Edit clearance on contracts; restricted elsewhere |

*(Note: The login screen includes a **One-Click Evaluator Persona Switcher** allowing judges to switch between these accounts instantly with 1 click).*

---

## Core Security Guarantees

1. **Default Deny Authorization (The Server Decides, Every Time):**
   - Access is evaluated under:
     $$\text{Access} = (\text{user.id} == \text{doc.owner\_id}) \lor (\text{active non-expired non-revoked grant exists})$$
   - Hiding a button is not security. Every view, download, update, and deletion is checked synchronously against the database.
2. **Immediate Revocation (Sub-Millisecond Effect):**
   - Taking access away terminates access instantly.
   - Dual-layer revocation: The `permissions` record is marked `is_revoked = True`, AND the target user's `token_generation` counter is bumped, invalidating all outstanding JWTs and refresh tokens immediately.
3. **Cryptographic Tamper-Evident Audit Trail:**
   - Every action (upload, download, edit, grant, revocation, and refused attempts) is recorded in an append-only log.
   - Each entry's hash incorporates the previous entry's hash using SHA-256 Merkle chaining:
     $$\text{entry\_hash} = \text{SHA256}(\text{prev\_hash} \parallel \text{action} \parallel \text{user} \parallel \text{doc} \parallel \text{details} \parallel \text{timestamp})$$
   - The UI includes a **"Verify Cryptographic Chain Integrity"** button that re-hashes the entire log from block #1 and pinpoints any altered row.
4. **Data at Rest Encryption:**
   - Files on disk are encrypted using **AES-256-GCM** with random 96-bit IVs and 128-bit authentication tags.
   - Files are stored using unguessable UUID filenames in `uploads/` outside the web root.
5. **AI Access Advisor (Zero Autonomous Grants):**
   - AI analyzes document sensitivity (e.g. salary vs. contract) and proposes collaborators.
   - The machine **never widens access on its own**. An authorized human must explicitly confirm, and both the AI suggestion and the human grant are recorded in the audit trail.

---

## Quickstart (Clean Clone Deployment)

### Prerequisites
- Python 3.10+ (tested on Python 3.12)
- Virtual environment (`venv`)

### 1. Setup & Dependencies
```powershell
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies (FastAPI, Argon2, SQLAlchemy, cryptography, PyJWT, aiosqlite, pytest)
pip install -r requirements.txt aiosqlite
```

### 2. Run Application
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser. The single-page dashboard and API are served directly.
Interactive OpenAPI documentation is available at **[http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs)**.

### 3. Run Automated Tests
```powershell
pytest -v
```
All 11 automated security tests run against an isolated in-memory test database, validating IDOR prevention, immediate revocation, brute-force rate limiting, AES-256 disk encryption, and cryptographic audit tampering detection.

---

## Project Structure

```
trustvault/
├── backend/
│   ├── app/
│   │   ├── middleware/      # Auth & rate-limiting middleware
│   │   ├── models/          # User, Document, Permission, AuditLog (Universal SQLite & PG)
│   │   ├── routers/         # auth, documents, permissions, audit, users, ai
│   │   ├── schemas/         # Pydantic validation models
│   │   ├── services/        # Business logic & cryptographic operations
│   │   ├── utils/           # Argon2id, AES-256-GCM, validators
│   │   ├── config.py        # Environment settings & fallback configuration
│   │   ├── database.py      # Async database connection & pooling
│   │   ├── main.py          # FastAPI application & security headers
│   │   └── seed.py          # Demo personas, sample confidential documents & audit seed
│   ├── tests/
│   │   ├── conftest.py              # Test database & client fixtures
│   │   ├── test_permissions.py      # IDOR & immediate revocation tests
│   │   ├── test_audit_chain.py      # Tamper detection tests
│   │   ├── test_auth_security.py    # Argon2id & rate-limiting tests
│   │   ├── test_encryption.py       # AES-256-GCM disk ciphertext tests
│   │   └── test_ai_advisor.py       # AI human-in-the-loop tests
│   ├── requirements.txt
│   └── pytest.ini
├── frontend/
│   ├── css/
│   │   └── styles.css       # Custom dark/glassmorphism design system
│   ├── js/
│   │   ├── api.js           # API client with token refresh & streaming download
│   │   └── app.js           # UI logic, strength meter, persona switcher & modals
│   └── index.html           # Single-page application dashboard
├── uploads/                 # AES-256-GCM encrypted document blobs
├── THREATS.md               # Complete threat matrix, defenses & accepted risks
├── PROMPTS.md               # 5 dated AI engineering & bug-correction entries
└── README.md                # Documentation & evaluation instructions
```
