# 🗳️ University E-Voting System — Progetto APS G25

> **Algorithms and Protocols for Security** — University of Salerno, 2026  
> WP1, WP2 & WP3: Model Specification, Architecture & Security Analysis

A **centralized yet cryptographically verifiable** electronic voting prototype designed for university referendums. The system mathematically decouples the voter's civil identity (managed by the University) from the expressed preference (managed by the Ballot Box), guaranteeing **Anonymity**, **Vote Uniqueness**, **Resilience**, and **Receipt-Freeness**.

---

## 👥 Group Members

<!-- ⚠️ Replace with actual names and matricola -->
| Name             | Matricola  |
| ---------------- | ---------- |
| *Name Surname 1* | `05XXXXXXX` |
| *Name Surname 2* | `05XXXXXXX` |
| *Name Surname 3* | `05XXXXXXX` |

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Cryptographic Protocols](#cryptographic-protocols)
- [Security Properties](#security-properties)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Usage Guide](#usage-guide)
- [Testing](#testing)
- [Documentation](#documentation)
- [Tech Stack](#tech-stack)

---

## Architecture Overview

The system follows a **three-entity trust model** that separates concerns by design:

```
┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│   Authentication │       │    Ballot Box     │       │  Bulletin Board  │
│   Server (SSO)   │       │     (Urna)        │       │   (Bacheca)      │
│                  │       │                   │       │                  │
│ • Identity check │       │ • Receives sealed │       │ • Public ledger  │
│ • Blind signing  │──────▶│   encrypted votes │──────▶│ • Merkle Tree    │
│ • Voter registry │       │ • Tally & decrypt │       │ • Audit & verify │
└──────────────────┘       └──────────────────┘       └──────────────────┘
        ▲                          ▲
        │   ┌──────────────────┐   │
        └───│  Client Wallet   │───┘
            │                  │
            │ • Token blinding │
            │ • Ballot encrypt │
            │ • Vote casting   │
            └──────────────────┘
```

### Protocol Flow

1. **Authentication** — The voter authenticates via OIDC SSO (simulated) with their university matricola.
2. **Blind Signature** — The client generates a random token `m`, applies Full-Domain Hash, blinds it with a random factor `r`, and sends the blinded value `m'` to the Authentication Server.
3. **Signing** — The server verifies eligibility, marks the student as "ballot withdrawn", and signs `m'` with its RSA private key → `s'`.
4. **Unblinding** — The client removes the blinding factor to obtain a valid signature `s` on `m`. The server never sees `m`, so the token is unlinkable to the voter's identity.
5. **Encrypted Vote** — The client packages `{preference, m, s, timestamp, h_bind}` into a JSON payload, encrypts it with **hybrid encryption** (RSA-OAEP + AES-256-GCM), and sends the sealed ballot to the Ballot Box.
6. **Tally** — Trustees present their Shamir shares to reconstruct the decryption key. The Ballot Box shuffles, decrypts, deduplicates (keeping the latest timestamp per token), and publishes results.
7. **Audit** — The Bulletin Board exposes a Merkle Tree over all valid tokens. Any voter can verify their vote's inclusion via a Merkle Proof.

---

## Cryptographic Protocols

| Mechanism | Algorithm | Purpose |
| --- | --- | --- |
| **Blind Signature** | RSA with Full-Domain Hash (FDH) | Unlinkable credential issuance |
| **Hybrid Encryption** | RSA-2048-OAEP + AES-256-GCM | Confidentiality + integrity of ballots |
| **Secret Sharing** | Shamir's Secret Sharing (t-of-n) | Distributed key management for the Ballot Box |
| **Integrity Audit** | Merkle Tree + SHA-256 | Tamper-evident public bulletin board |
| **Binding Hash** | SHA-256 over `preference ‖ token ‖ timestamp` | Prevents payload manipulation |
| **Root Signature** | RSA-PSS | Authenticity seal on the Merkle root |
| **Authentication** | OpenID Connect (OIDC) mock | University SSO simulation |

---

## Security Properties

| Property | Mechanism |
| --- | --- |
| **Anonymity** | Blind signature decouples identity from token; the Authentication Server never sees `m` |
| **Vote Uniqueness** | Each matricola can withdraw exactly one blind-signed ballot |
| **Receipt-Freeness** | Voters can re-submit with the same token; only the latest timestamp is counted at tally |
| **Resilience** | Shamir (t, n) threshold: no single party can decrypt alone; quorum of trustees required |
| **Integrity** | AES-GCM authenticated encryption; Merkle Tree for public audit |
| **Verifiability** | Any voter can verify their token's inclusion via Merkle Proof against the signed root |

---

## Project Structure

```
ProgettoAPS-G25/
├── run.py                          # Application entry point (Flask server)
├── requirements.txt                # Python dependencies
├── README.md
│
├── app/
│   ├── __init__.py                 # Flask app factory & global instances
│   ├── routes.py                   # API endpoints & page routes
│   │
│   ├── core/                       # Cryptographic backend
│   │   ├── auth_server.py          # Authentication Server (RSA blind signing)
│   │   ├── client_wallet.py        # Client-side wallet (blinding, encryption)
│   │   ├── urna.py                 # Ballot Box (Shamir, decryption, tally)
│   │   ├── bacheca.py              # Bulletin Board (Merkle Tree, audit)
│   │   └── mock_oidc_server.py     # Simulated OIDC Identity Provider
│   │
│   ├── templates/                  # Jinja2 HTML templates
│   │   ├── layout.html             # Base layout
│   │   ├── index.html              # Homepage
│   │   ├── elettore.html           # Voter dashboard
│   │   ├── admin.html              # Admin / tally panel
│   │   ├── bacheca.html            # Public bulletin board
│   │   └── oidc_login.html         # SSO login form
│   │
│   └── static/                     # Frontend assets
│       ├── style.css               # Stylesheet
│       └── app.js                  # Client-side logic
│
├── tests/                          # Test suite & simulations
│   ├── test_voting_system.py       # Unit tests (unittest)
│   ├── main_simulation.py          # Full end-to-end simulation
│   ├── main_test1.py               # Additional test scenarios
│   ├── benchmark.py                # Performance benchmarks
│   └── benchmark_extended.py       # Extended benchmarks
│
└── Documents/                      # Project documentation
    ├── Progetto_APS.pdf            # Full project report
    └── ProjectWork.pdf             # Project work specification
```

---

## Getting Started

### Prerequisites

- **Python 3.10+** (tested on 3.12)
- **pip** package manager

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/aleferrara16/ProgettoAPS-G25.git
cd ProgettoAPS-G25

# 2. Create a virtual environment (recommended)
python -m venv .venv

# 3. Activate it
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

### Run the Application

```bash
python run.py
```

The Flask server starts at **http://127.0.0.1:5000**.

---

## Usage Guide

### As a Voter (`/elettore`)

1. **Login** — Enter one of the pre-registered matricole: `10002345`, `10005678`, `10009101`.  
   Alternatively, use the **SSO Login** button to authenticate via the mock OIDC flow.
2. **Request Blind Token** — Click the button to generate, blind, sign, and unblind the voting credential in one step.
3. **Cast Vote** — Select your preference (`SI`, `NO`, `SCHEDA BIANCA`, `NULLA`) and submit your encrypted ballot.

### As an Admin (`/admin`)

1. View the number of sealed ballots received.
2. Click **Start Tally** to present trustee shares, reconstruct the decryption key, and compute the results.

### Bulletin Board (`/bacheca`)

- View all published (anonymous) votes after the tally.
- Enter a token to verify its Merkle Proof against the signed Merkle Root.

---

## Testing

### Unit Tests

```bash
python -m pytest tests/test_voting_system.py -v
```

The test suite covers:

| Test | Description |
| --- | --- |
| `test_successful_vote_flow` | Full end-to-end vote: authentication → blind signature → encryption → tally → Merkle verification |
| `test_double_voting_at_auth_server` | Rejects a second blind token request for the same matricola |
| `test_double_voting_and_receipt_freeness` | Deduplication keeps only the latest timestamp (receipt-freeness) |
| `test_quorum_not_reached` | Tally fails when fewer than `t` Shamir shares are presented |
| `test_invalid_signature_rejection` | Forged signatures are detected and ballots are discarded |

### End-to-End Simulation

```bash
python tests/main_simulation.py
```

Runs a full scenario including regular voting, double-voting attack, coercion & receipt-freeness simulation, malformed payload injection, and Merkle Tree audit.

### Benchmarks

```bash
python tests/benchmark.py
python tests/benchmark_extended.py
```

---

## Documentation

Detailed project documentation is available in the `Documents/` directory:

- **`Progetto_APS.pdf`** — Complete project report with formal model specification, threat model, and security analysis.
- **`ProjectWork.pdf`** — Original project work assignment and requirements.

---

## Tech Stack

| Layer | Technology |
| --- | --- |
| **Backend** | Python 3, Flask |
| **Cryptography** | `cryptography` (RSA, AES-GCM, SHA-256, RSA-PSS) |
| **Authentication** | Authlib (OIDC), mock Identity Provider |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript, Jinja2 |
| **Testing** | unittest, custom simulations & benchmarks |

---

<p align="center">
  <sub>University of Salerno — Algorithms and Protocols for Security — A.Y. 2025/2026</sub>
</p>
