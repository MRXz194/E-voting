# 🗳️ SecureVote — Cryptographic E-Voting System

> A production-ready, end-to-end encrypted electronic voting system built with **Flask**, **ElGamal Homomorphic Encryption**, and **RSA Blind Signatures**. Designed for academic demonstration of privacy-preserving cryptographic protocols in democratic elections.

---

## 📑 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Cryptographic Protocols](#cryptographic-protocols)
- [Pages & UI](#pages--ui)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Database Schema](#database-schema)
- [API Reference](#api-reference)
- [Getting Started](#getting-started)
- [Running Tests](#running-tests)
- [Stress Testing](#stress-testing)
- [Access Control](#access-control)
- [Security Considerations](#security-considerations)
- [Known Limitations](#known-limitations)
- [License](#license)

---

## Overview

SecureVote implements a **three-authority architecture** for anonymous, verifiable electronic voting:

| Authority | Role | Key Material |
|---|---|---|
| **Election Authority (EA)** | Manages election lifecycle, decrypts final tally | ElGamal keypair (256-bit safe prime) |
| **Registration Authority (RA)** | Issues anonymous voting credentials via blind signature | RSA keypair (512-bit) |
| **Voter** | Casts encrypted ballot without revealing identity | Ephemeral token + blinding factor |

The system guarantees:
- ✅ **Ballot secrecy** — no one can link a vote to a voter (blind signature decouples identity from credential)
- ✅ **Universal verifiability** — anyone can verify the tally via the public bulletin board
- ✅ **Eligibility** — only registered voters with valid secret codes can obtain credentials
- ✅ **Double-vote prevention** — `token_hash` uniqueness enforced at DB level (UNIQUE constraint)
- ✅ **Integrity protection** — HMAC-SHA256 prevents ballot tampering in transit

---

## Key Features

- 🔐 **ElGamal Homomorphic Encryption** — votes are tallied *without* decrypting individual ballots
- ✍️ **RSA Blind Signatures (Chaum's Protocol)** — anonymous credential issuance; RA signs without seeing the token
- 🔗 **HMAC-SHA256 Packet Integrity** — every ballot packet is signed to prevent tampering
- 📋 **Public Bulletin Board** — append-only encrypted ballot ledger, publicly auditable
- 🗳️ **Multi-Candidate Support** — each ballot encrypts a vote vector (one ciphertext per candidate)
- 📊 **Real-time Tally** — Shanks' Baby-Step Giant-Step (BSGS) algorithm to recover discrete log vote counts
- ⚡ **Async Registration** — Celery + Redis for offloading RSA signing under high load
- 🔒 **Role-based Access Control** — Admin / Voter / Guest session management with decorators
- 🧪 **22+ Automated Tests** — covering crypto primitives, attack resistance, security scenarios, and API correctness
- 📈 **Load Testing** — Locust stress test with full voting flow for up to 10,000 concurrent voters

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT BROWSER                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Voter Dashboard (voter_dashboard.html)                  │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │   │
│  │  │ 1. Blind     │  │ 2. Encrypt   │  │ 3. Submit    │  │   │
│  │  │  Token Gen   │→ │  Ballot      │→ │  via API     │  │   │
│  │  │  (crypto.js) │  │  (ElGamal)   │  │  /api/vote   │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬──────────────────────────────────┘
                               │ HTTPS
┌──────────────────────────────▼──────────────────────────────────┐
│                         FLASK APP (app.py)                       │
│                                                                  │
│  /api/public-keys    →  Returns ElGamal + RSA public keys       │
│  /api/register/sync  →  Issues RSA blind signature (sync)       │
│  /api/register/async →  Offloads RSA sign to Celery worker      │
│  /api/register/result/<id> → Polls async signing result         │
│  /api/vote           →  Verifies HMAC + credential → stores     │
│  /admin              →  Election lifecycle management           │
│  /bulletin_board     →  Public read-only ballot ledger          │
│                                                                  │
│  Decorators: @admin_required, @voter_required                   │
└──────────────┬───────────────────────────┬──────────────────────┘
               │ SQLAlchemy                │ Celery (Redis broker)
┌──────────────▼──────────────┐  ┌─────────▼─────────────────────┐
│       SQLite DATABASE       │  │     Celery Worker (tasks.py)  │
│  election_config            │  │  sign_blinded_token_task()    │
│  voters                     │  │  → RSA modular exponentiation │
│  ballots (append-only)      │  │  → Result stored in Redis    │
└─────────────────────────────┘  └───────────────────────────────┘
```

---

## Cryptographic Protocols

### 1. RSA Blind Signature — Anonymous Credential (Chaum, 1983)

Used to issue voting credentials without the RA learning *which token* was signed.

**Implementation:** [`crypto/blind_sig.py`](crypto/blind_sig.py)

```
Voter:     t ← random token (string)
           H(t) = SHA-256(t) mod N                     (hash to integer)
           r ← random blinding factor, gcd(r, N) = 1
           t̃ = H(t) × r^e mod N                        (blind the hash)

RA:        s̃ = t̃^d mod N                               (sign without seeing t)

Voter:     s = s̃ × r⁻¹ mod N                           (unblind → real signature)
           Credential = (t, s)

Verify:    s^e mod N ≡ H(t) mod N                      (standard RSA verify)
```

### 2. ElGamal Homomorphic Encryption

Each candidate gets one ciphertext per ballot. Ciphertexts multiply homomorphically to aggregate votes.

**Implementation:** [`crypto/elgamal.py`](crypto/elgamal.py)

```
KeyGen:    p = 2q + 1  ← safe prime (256-bit)
           g ← generator of Z_p* (quadratic residue)
           x ← random secret key (EA only)
           y = g^x mod p (public key)

Encrypt:   m = g^vote mod p        (encode: vote=0 → m=1, vote=1 → m=g)
           k ← random nonce
           C1 = g^k mod p
           C2 = m × y^k mod p

Tally:     C1_agg = ∏ C1_i mod p   (multiply all C1 values)
           C2_agg = ∏ C2_i mod p   (multiply all C2 values)
           g^sum  = Decrypt(C1_agg, C2_agg)

Recover:   Baby-Step Giant-Step to find sum from g^sum
           Complexity: O(√N) where N = max voters
```

### 3. HMAC-SHA256 Ballot Integrity

Every submitted ballot packet is integrity-protected against tampering in transit.

**Implementation:** [`crypto/hmac_utils.py`](crypto/hmac_utils.py)

```
Key Derivation:  key = SHA-256("token:credential")
Payload:         payload = "token|c1_json|c2_json"
HMAC:            HMAC-SHA256(key, payload)
```

### 4. Cryptographic Utility Functions

**Implementation:** [`crypto/utils.py`](crypto/utils.py)

| Function | Description |
|---|---|
| `mod_pow(base, exp, mod)` | Fast modular exponentiation (square-and-multiply) |
| `extended_gcd(a, b)` | Extended Euclidean algorithm → `(gcd, x, y)` |
| `mod_inverse(a, m)` | Modular multiplicative inverse via extended GCD |
| `is_prime(n, k=20)` | Miller-Rabin primality test with 20 rounds |
| `generate_prime(bits)` | Random prime generation |
| `generate_safe_prime(bits)` | Safe prime `p = 2q + 1` generation |
| `find_generator(p)` | Generator of Z_p* for safe prime p |
| `baby_step_giant_step(g, target, p, max_val)` | BSGS discrete log solver |

---

## Pages & UI

| Page | URL | Access | Description |
|---|---|---|---|
| **System Overview** | `/` | Public | Election status, live stats, results after tally |
| **Login** | `/login` | Public | Admin login (credentials) or voter login (voter ID + secret code) |
| **Admin Console** | `/admin` | Admin only | Manage voters, view results, control election phases |
| **Setup** | `/setup` | Admin only | Configure election name and candidate list |
| **Voter Dashboard** | `/voter_dashboard` | Voter only | 4-step voting wizard (register → encrypt → submit) |
| **Public Ledger** | `/bulletin_board` | Public | Append-only encrypted ballot archive |
| **Security** | `/security` | Public | Cryptographic architecture documentation |
| **Receipt** | `/receipt?r=<hash>` | Public | Vote receipt display |
| **Verify** | `/verify/<hash>` | Public | Receipt verification against bulletin board |

### Election Lifecycle (Admin)

```
Setup ──→ Voting (Active) ──→ Tallying (Closed)
  │              │                    │
  │      Voters register        Results computed
  │      & cast ballots       (homomorphic tally)
  │              │                    │
  └──── Reset ←──┘            Winner announced
```

**Status transitions:** `setup` → `voting` → `tallying`

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.10+, Flask 3.0.3 |
| **Database** | SQLite + Flask-SQLAlchemy 3.1.1 (NullPool for Celery compatibility) |
| **Crypto (Server)** | Pure Python — `crypto/` module (no external crypto libs) |
| **Crypto (Client)** | Vanilla JS with Web Crypto API — `static/crypto.js` |
| **Task Queue** | Celery 5.4.0 + Redis 5.0.7 (async RSA signing) |
| **Frontend** | Jinja2 Templates, Vanilla JS, Tailwind CSS (CDN) |
| **Icons** | Google Material Symbols |
| **Fonts** | Inter + Plus Jakarta Sans (Google Fonts) |
| **Testing** | pytest 8.2.0 |
| **Load Testing** | Locust 2.29.0 |

---

## Project Structure

```
E-voting/
├── app.py                  # Main Flask application & all routes (529 lines)
├── models.py               # SQLAlchemy models (ElectionConfig, Voter, Ballot)
├── tasks.py                # Celery task factory (async RSA signing)
├── locustfile.py           # Locust load test — full voting flow
├── requirements.txt        # Python dependencies
├── README.md               # This file
│
├── crypto/                 # Pure-Python cryptographic primitives
│   ├── __init__.py
│   ├── elgamal.py          # ElGamal keygen, encrypt, decrypt, homomorphic tally
│   ├── blind_sig.py        # RSA keygen, blind, sign, unblind, verify (Chaum)
│   ├── hmac_utils.py       # HMAC-SHA256 packet signing & verification
│   └── utils.py            # Modular arithmetic, primes, BSGS, SHA-256 helpers
│
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Global layout, Tailwind CDN, Material Icons
│   ├── index.html          # System Overview / Public Dashboard
│   ├── login.html          # Admin + Voter login (role-based forms)
│   ├── admin_dashboard.html# Admin Console (voters, results, crypto keys tabs)
│   ├── voter_dashboard.html# Voter 4-step voting wizard
│   ├── bulletin_board.html # Public encrypted ballot ledger
│   ├── security.html       # Cryptographic architecture reference page
│   ├── setup.html          # Election configuration form
│   ├── admin.html          # Redirect shim → admin_dashboard
│   ├── vote.html           # Legacy standalone vote page
│   ├── register.html       # Legacy registration page
│   ├── receipt.html        # Vote receipt display
│   ├── tally.html          # Standalone tally results page
│   └── verify.html         # Receipt verification page
│
├── static/
│   ├── crypto.js           # Client-side BigInt crypto (ElGamal, RSA Blind, HMAC)
│   └── style.css           # Custom stylesheets
│
├── tests/
│   ├── test_crypto.py      # Unit tests: ElGamal homomorphic, RSA blind sig, BSGS
│   ├── test_api.py         # Integration tests: login, setup, API endpoints
│   ├── test_security.py    # 10 security tests: double-vote, forgery, HMAC, etc.
│   ├── test_scenarios.py   # Scenario tests: unauthorized voter, HMAC tampering
│   └── test_attack_zkp.py  # ZKP vulnerability demonstration (vote inflation)
│
└── instance/
    └── evoting.db          # SQLite database (auto-created on first run)
```

---

## Database Schema

### `election_config`

| Column | Type | Description |
|---|---|---|
| `id` | Integer PK | Auto-increment |
| `election_name` | String(200) | Election title |
| `candidates` | Text | JSON array of candidate names |
| `status` | String(20) | `setup` → `voting` → `tallying` |
| `eg_p`, `eg_g`, `eg_y` | Text | ElGamal public key (EA) |
| `eg_x` | Text | ElGamal private key (EA) — demo only |
| `rsa_N`, `rsa_e` | Text | RSA public key (RA) |
| `rsa_d` | Text | RSA private key (RA) — demo only |
| `created_at` | DateTime | Timestamp |

### `voters`

| Column | Type | Description |
|---|---|---|
| `id` | Integer PK | Auto-increment |
| `voter_id` | String(100) UNIQUE | Voter identifier |
| `name` | String(200) | Voter display name |
| `secret_code` | String(10) | 6-digit random login code (generated by admin) |
| `status` | String(20) | `registered` → `credential_issued` → `voted` |
| `registered_at` | DateTime | Registration timestamp |
| `voted_at` | DateTime | Vote submission timestamp (null until voted) |

### `ballots` (Bulletin Board — append-only)

| Column | Type | Description |
|---|---|---|
| `id` | Integer PK | Auto-increment |
| `token_hash` | String(64) UNIQUE | SHA-256(token) — prevents double voting |
| `c1` | Text | JSON array of ElGamal C1 values (one per candidate) |
| `c2` | Text | JSON array of ElGamal C2 values (one per candidate) |
| `receipt` | String(64) | SHA-256(c1_json + c2_json + timestamp) — verifiable receipt |
| `submitted_at` | DateTime | Submission timestamp |

---

## API Reference

### `GET /api/public-keys`

Returns ElGamal and RSA public keys for client-side encryption.

**Response (200):**
```json
{
  "elgamal": { "p": "...", "g": "...", "y": "..." },
  "rsa": { "N": "...", "e": "..." }
}
```

---

### `POST /api/register/sync`

Issues an RSA blind signature credential (synchronous — immediate response).

**Request:**
```json
{
  "voter_id": "voter1",
  "secret_code": "482910",
  "blinded_token": "3828194..."
}
```

**Response (200):**
```json
{ "blind_signature": "7a2f93..." }
```

**Error Responses:**

| Status | Condition |
|---|---|
| `404` | Voter ID does not exist |
| `403` | Invalid secret code |
| `400` | Credential already issued |

---

### `POST /api/register/async`

Offloads RSA blind signing to a Celery worker (for high-load scenarios).

**Request:** Same as `/api/register/sync`

**Response (200):**
```json
{ "task_id": "abc123-def456-..." }
```

---

### `GET /api/register/result/<task_id>`

Polls the result of an async registration task.

**Response:**
```json
// Pending
{ "status": "pending" }

// Complete
{ "status": "done", "blind_signature": "7a2f93..." }

// Failed
{ "status": "failed", "error": "..." }
```

---

### `POST /api/vote`

Submits an encrypted ballot. Verifies HMAC integrity → RSA credential → token uniqueness before storing.

**Request:**
```json
{
  "token": "tok_voter1_8294710382",
  "credential": "918273645...",
  "c1_array": "[\"123...\", \"456...\"]",
  "c2_array": "[\"789...\", \"012...\"]",
  "packet_hmac": "a1b2c3d4e5f6...",
  "voter_id_for_ui": "voter1"
}
```

**Validation Pipeline:**
1. ✅ Election status must be `voting`
2. ✅ HMAC verification (if provided) — detects ciphertext tampering
3. ✅ RSA credential verification — `signature^e mod N == H(token) mod N`
4. ✅ Token hash uniqueness — prevents double voting

**Response (200):**
```json
{ "status": "success", "receipt": "sha256hash..." }
```

**Error Responses:**

| Status | Condition |
|---|---|
| `400` | Voting not open / incomplete data / HMAC mismatch |
| `403` | Invalid RSA credential (forged or wrong token) |
| `409` | Token already used (double-vote attempt) |

---

## Getting Started

### Prerequisites

- **Python 3.10+**
- **Redis** (optional — only needed for Celery async registration under load)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/MRXz194/E-voting.git
cd E-voting

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
```

The app will be available at **http://localhost:5000**

### Optional: Start Celery Worker (for async registration)

```bash
# Terminal 1: Start Redis (required for Celery)
redis-server

# Terminal 2: Start Celery worker
celery -A app.celery worker --loglevel=info --pool=solo
```

### Default Credentials

| Role | Login | Password / Code |
|---|---|---|
| **Admin** | `admin` | `admin` |
| **Voter** | Voter ID (e.g. `voter1`) | 6-digit secret code shown in Admin Console |

### Quick Demo Flow

1. Open **http://localhost:5000** → Click **Login**
2. Login as **admin** (`admin` / `admin`) → go to **Admin Console**
3. Enter election name and candidates (comma-separated) → click **Create Election**
4. Click **Add 10 Demo Voters** for quick setup or add individually
5. Click **Open Voting** to start the voting phase
6. Logout → Login as a **voter** using Voter ID + secret code (shown in admin panel)
7. Complete the 4-step voting wizard on **Voter Dashboard**:
   - Step 1: Generate & blind a random token
   - Step 2: Request RA to sign the blinded token
   - Step 3: Unblind signature → obtain anonymous credential
   - Step 4: Encrypt vote (ElGamal) + compute HMAC → submit
8. Login as admin → click **Close Voting** to trigger homomorphic tally
9. View results in **Admin Console** and **System Overview** (`/`)

---

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test modules
pytest tests/test_crypto.py -v       # Crypto primitives (4 tests)
pytest tests/test_api.py -v          # API workflow (1 integration test)
pytest tests/test_security.py -v     # Security & attack resistance (10 tests)
pytest tests/test_scenarios.py -v    # Edge-case scenarios (4 tests)
pytest tests/test_attack_zkp.py -v   # ZKP vulnerability demo (1 test)

# Run with short traceback
pytest tests/ --tb=short
```

### Test Coverage

| Test File | Tests | Covers |
|---|---|---|
| `test_crypto.py` | 4 | ElGamal homomorphic tally, RSA blind sig full cycle, mod inverse, BSGS |
| `test_api.py` | 1 | Full API workflow: login → setup → add voter → open voting → get keys |
| `test_security.py` | 10 | Happy path, double-vote (×1 & ×1000), credential reuse, registration abuse, forged credential, HMAC tampering, wrong secret code, voting outside phase (×2), unauthorized voter, ballot count integrity |
| `test_scenarios.py` | 4 | Unauthorized registration, HMAC tampering, closed-session vote, premature tally |
| `test_attack_zkp.py` | 1 | ZKP vulnerability: vote inflation attack (encoding 1000 instead of 0/1) |

### Notable Test: ZKP Vulnerability Demo

`test_attack_zkp.py` demonstrates a **known limitation**: without Zero-Knowledge Proofs, a malicious voter can encrypt `g^1000` instead of `g^0` or `g^1`, inflating their vote count. This test intentionally passes to document the vulnerability.

---

## Stress Testing

The project includes a comprehensive **Locust** load test that simulates the full voting cycle.

### Setup

```bash
# 1. Seed 10,000 test voters into the database
# (Create a seed script or use the admin bulk-add feature)

# 2. Ensure the election is configured and voting is open

# 3. Start Locust with Web UI
locust -f locustfile.py --host=http://localhost:5000

# 4. Or run headless
locust -f locustfile.py --host=http://localhost:5000 \
  -u 1000 -r 100 --run-time 60s --headless
```

### Locust Workflow Per User

Each simulated user executes the complete voting flow:

```
1. Load public keys (cached globally)
2. Generate random token → blind with RSA public key
3. POST /api/register/sync → receive blind signature
4. Unblind signature → obtain anonymous credential
5. Encrypt vote for random candidate (ElGamal, 3 candidates)
6. Compute HMAC-SHA256 for packet integrity
7. POST /api/vote → submit encrypted ballot
8. Reset with new voter ID → repeat
```

### Locust Parameters

| Parameter | Value |
|---|---|
| Wait time | 0.5–2 seconds between requests |
| Voter pool | 10,000 pre-seeded voters (`stress_voter_0` to `stress_voter_9999`) |
| Candidates | 3 (hardcoded in stress test) |
| Crypto ops | Real ElGamal encryption + RSA blind signature (not mocked) |

---

## Access Control

```
Route                     Guest   Voter   Admin
──────────────────────────────────────────────────
/                           ✅      ✅      ✅
/login                      ✅      ✅      ✅
/logout                     ✅      ✅      ✅
/bulletin_board             ✅      ✅      ✅
/security                   ✅      ✅      ✅
/receipt                    ✅      ✅      ✅
/verify/<hash>              ✅      ✅      ✅
/voter_dashboard            ❌      ✅      ❌
/admin                      ❌      ❌      ✅
/setup                      ❌      ❌      ✅
/admin/add-voter            ❌      ❌      ✅
/admin/add-bulk-voters      ❌      ❌      ✅
/admin/open-voting          ❌      ❌      ✅
/admin/close-voting         ❌      ❌      ✅
/tally                      ❌      ❌      ✅
/api/public-keys            ✅      ✅      ✅
/api/register/sync          ✅      ✅      ✅    (requires valid voter_id)
/api/register/async         ✅      ✅      ✅    (requires valid voter_id)
/api/vote                   ✅      ✅      ✅    (requires valid credential)
```

> **Note:** API endpoints use credential-based authentication (RSA blind signature verification) rather than session-based role checks, enabling anonymous voting.

---

## Security Considerations

> ⚠️ This system is designed for **academic and demonstration purposes**. For production deployment, the following must be addressed:

| Issue | Current State | Recommendation |
|---|---|---|
| **Key storage** | RSA/ElGamal private keys stored in SQLite | Use HSM or KMS (AWS KMS, Azure Key Vault) |
| **Flask secret key** | Hardcoded fallback `"super-secret-..."` | Always set `FLASK_SECRET_KEY` via environment variable |
| **Key separation** | EA and RA on same server | Separate entities on isolated, air-gapped systems |
| **HTTPS** | Not enforced | Deploy behind TLS (Nginx + Let's Encrypt) |
| **Admin credentials** | Hardcoded `admin`/`admin` | Implement proper authentication (OAuth2, LDAP) |
| **Threshold crypto** | Single EA holds full private key | Use threshold ElGamal (k-of-n decryption) |
| **ZK Proofs** | ❌ Not implemented | Add ZKP for ballot validity (proof of 0-or-1 encryption) |
| **Audit logging** | Basic DB timestamps only | Enable WAL mode, ship logs to append-only audit store |
| **Rate limiting** | None | Add rate limiting to API endpoints |
| **SQLite concurrency** | NullPool for Celery | Use PostgreSQL for production workloads |

---

## Known Limitations

1. **No Zero-Knowledge Proofs (ZKP):** A malicious voter can encrypt arbitrary values (e.g., `g^1000`) instead of `g^0` or `g^1`, inflating vote counts. The `test_attack_zkp.py` test demonstrates this vulnerability.

2. **Key size:** ElGamal uses 256-bit safe primes and RSA uses 512-bit keys — adequate for demonstration but insufficient for production (recommend 2048+ bit RSA, 2048+ bit ElGamal).

3. **Discrete log recovery:** The BSGS tally recovery has O(√N) complexity, which limits the practical voter count. For very large elections, use alternative encoding schemes.

4. **Single-server architecture:** EA and RA are co-located. In a real election, these must be operated by separate, mutually distrustful entities.

---

## License

MIT License — for academic and educational use.

---

*SecureVote — End-to-end encrypted e-voting with homomorphic tallying.*
*Cryptographic Protocol v2.1 | Flask + ElGamal + RSA Blind Signature + HMAC-SHA256*
