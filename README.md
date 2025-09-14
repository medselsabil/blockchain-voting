# Blockchain Voting System

A secure, transparent, and tamper-resistant voting system implemented using blockchain principles and cryptography. Built with Python and Streamlit for demonstration purposes.

---

## Features

- Transparency: All votes stored on an immutable blockchain ledger.
- Security: Cryptography prevents tampering and ensures vote authenticity.
- Privacy: Votes are encrypted; voter identities are hidden.
- Trust: Decentralized validation removes single points of failure.
- Tampering Demo: Modify a vote to see how blockchain detects it.

---

## System Architecture

- Block Structure: index, timestamp, previous hash, encrypted votes, nonce, hash
- Blockchain: Proof-of-work mining, validation, and tamper detection
- Cryptography:
  - Fernet encryption for votes
  - RSA digital signatures for authenticity
  - SHA-256 hashing for block linkage

---

## Workflow

1. Voter casts a vote → encrypted + signed
2. Pending votes collected
3. Miner solves proof-of-work → block created
4. Blockchain updated → votes validated
5. Results tallied securely

---

## Tech Stack

- Frontend: Streamlit
- Backend: Python + Pandas
- Security: `hashlib`, `cryptography` libraries

---

## Installation

1. Clone the repository:
```bash
git clone https://github.com/YourUsername/blockchain-voting.git
cd blockchain-voting

