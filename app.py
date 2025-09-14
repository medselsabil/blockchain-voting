import streamlit as st
import hashlib
import time
from datetime import datetime
import pandas as pd
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet

# Page config
st.set_page_config(page_title="Blockchain Voting System", layout="wide")

# ---------------- Blockchain Classes ----------------

class Block:
    def __init__(self, index, prev_hash, encrypted_votes, timestamp, nonce=0, difficulty=4):
        self.index = index
        self.prev_hash = prev_hash
        self.encrypted_votes = encrypted_votes
        self.timestamp = timestamp
        self.nonce = nonce
        self.difficulty = difficulty
        self.hash = self.compute_hash()

    def compute_hash(self):
        votes_str = "".join(str(vote) for vote in self.encrypted_votes)
        return hashlib.sha256(f"{self.index}{self.prev_hash}{votes_str}{self.timestamp}{self.nonce}{self.difficulty}".encode()).hexdigest()

class Blockchain:
    def __init__(self, difficulty=4):
        self.chain = [Block(0, "0", ["Genesis Block"], time.time(), difficulty=0)]
        self.pending_votes = []
        self.difficulty = difficulty
        self.candidates = ["Candidate A", "Candidate B", "Candidate C"]
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        
        # Generate election authority key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
    
    def sign_vote(self, vote_data):
        """Sign vote data with authority private key"""
        signature = self.private_key.sign(
            vote_data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, vote_data, signature):
        """Verify vote signature using authority public key"""
        try:
            self.public_key.verify(
                signature,
                vote_data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
    
    def encrypt_vote(self, vote_data):
        """Encrypt vote data"""
        return self.fernet.encrypt(vote_data.encode()).decode()
    
    def decrypt_vote(self, encrypted_data):
        """Decrypt vote data"""
        return self.fernet.decrypt(encrypted_data.encode()).decode()

    def add_vote(self, voter_id, candidate):
        # Create vote data
        vote_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        vote_data = f"{voter_id}|{candidate}|{vote_timestamp}"
        
        # Encrypt voter ID and candidate for privacy
        encrypted_voter = self.encrypt_vote(voter_id)
        encrypted_candidate = self.encrypt_vote(candidate)
        
        # Sign the vote
        signature = self.sign_vote(vote_data)
        
        # Store encrypted vote with signature
        self.pending_votes.append({
            'encrypted_voter': encrypted_voter,
            'encrypted_candidate': encrypted_candidate,
            'timestamp': vote_timestamp,
            'signature': signature.hex()
        })
        return True, "Vote submitted"

    def mine_block(self):
        if not self.pending_votes:
            return None, "No votes to mine", 0, 0
        
        prev = self.chain[-1]
        start_time = time.time()
        
        block = Block(len(self.chain), prev.hash, self.pending_votes.copy(), time.time(), difficulty=self.difficulty)
        target = '0'*self.difficulty
        nonce = 0
        
        while True:
            block.nonce = nonce
            block.hash = block.compute_hash()
            if block.hash.startswith(target):
                mining_time = time.time() - start_time
                self.chain.append(block)
                self.pending_votes = []
                return block, "Block mined successfully", nonce+1, mining_time
            nonce += 1

    def get_results(self):
        res = {c:0 for c in self.candidates}
        for b in self.chain[1:]:
            for v in b.encrypted_votes:
                if isinstance(v, dict):
                    try:
                        candidate = self.decrypt_vote(v['encrypted_candidate'])
                        if candidate in res:
                            res[candidate] += 1
                    except:
                        continue
        return res

    def verify_integrity(self):
        # Verify genesis block
        g = self.chain[0]
        if g.index != 0 or g.prev_hash != "0" or g.hash != g.compute_hash():
            return False, "Genesis block invalid"
        
        # Verify all blocks
        for i in range(1, len(self.chain)):
            c, p = self.chain[i], self.chain[i-1]
            
            # Check block hash and proof of work
            if c.hash != c.compute_hash():
                return False, f"Block {i} hash invalid - content has been tampered with"
            
            if not c.hash.startswith('0'*c.difficulty):
                return False, f"Block {i} proof-of-work invalid - difficulty requirement not met"
                
            if c.prev_hash != p.hash:
                return False, f"Block {i} linkage invalid - previous hash doesn't match"
            
            # Verify signatures in votes
            for j, vote in enumerate(c.encrypted_votes):
                if isinstance(vote, dict):
                    try:
                        # Reconstruct vote data
                        voter_id = self.decrypt_vote(vote['encrypted_voter'])
                        candidate = self.decrypt_vote(vote['encrypted_candidate'])
                        vote_data = f"{voter_id}|{candidate}|{vote['timestamp']}"
                        
                        # Verify signature using authority public key
                        if not self.verify_signature(vote_data, bytes.fromhex(vote['signature'])):
                            return False, f"Signature invalid in block {i}, vote {j+1} - vote has been tampered with"
                    except:
                        return False, f"Error verifying vote in block {i}, vote {j+1}"
        
        return True, "Blockchain integrity verified"
    
    def modify_last_vote(self):
        """Modify the last vote in the blockchain (for demonstration purposes)"""
        if len(self.chain) <= 1:
            return False, "No blocks with votes to modify"
            
        last_block = self.chain[-1]
        if not last_block.encrypted_votes or not isinstance(last_block.encrypted_votes[0], dict):
            return False, "No votes to modify in the last block"
        
        # Get the first vote in the last block
        vote_to_modify = last_block.encrypted_votes[0]
        
        # Decrypt the candidate
        original_candidate = self.decrypt_vote(vote_to_modify['encrypted_candidate'])
        
        # Choose a random different candidate
        other_candidates = [c for c in self.candidates if c != original_candidate]
        if not other_candidates:
            return False, "No alternative candidates available"
        
        new_candidate = random.choice(other_candidates)
        
        # Re-encrypt with the new candidate but keep the original signature
        vote_to_modify['encrypted_candidate'] = self.encrypt_vote(new_candidate)
        
        # The block hash is now invalid because we changed the vote content
        # But we don't recalculate the hash to demonstrate tampering
        
        return True, f"Modified vote from '{original_candidate}' to '{new_candidate}'. Signature is now invalid."

# ---------------- Streamlit Session ----------------

if 'bc' not in st.session_state:
    st.session_state.bc = Blockchain(difficulty=4)

if 'voter_id' not in st.session_state:
    st.session_state.voter_id = 1000

st.title("🗳️ Blockchain Voting System \U0001F5F3")

col1, col2 = st.columns([2, 1])

# ---- Voting ----
with col1:
    st.subheader("Cast Your Vote")
    
    voter_id = f"V{st.session_state.voter_id}"
    st.info(f"Your voter ID: {voter_id}")
    
    candidate = st.radio("Choose candidate:", st.session_state.bc.candidates)
    
    if st.button("Submit Vote"):
        st.session_state.bc.add_vote(voter_id, candidate)
        st.success("✅ Vote submitted and signed")
        st.session_state.voter_id += 1

# ---- Mining ----
with col2:
    st.subheader("Mining")
    st.info(f"Fixed Difficulty: {st.session_state.bc.difficulty}")
    if st.button("Mine Block"):
        blk, msg, attempts, mining_time = st.session_state.bc.mine_block()
        if blk:
            st.success(f"{msg} in {mining_time:.2f} seconds")
            st.info(f"Attempts: {attempts}")
        else:
            st.warning(msg)

# ---- Tampering Section ----
st.subheader("Vote Tampering Demonstration")


if st.button("Modify Last Vote in Blockchain"):
    success, message = st.session_state.bc.modify_last_vote()
    if success:
        st.error(f"🔓 {message}")
        
        # Run integrity check to show what fails
        st.info("Running integrity check to detect tampering...")
        
        # Create a visual step-by-step verification process
        with st.expander("Detailed Integrity Check Results", expanded=True):
            st.write("Checking genesis block... ✅")
            
            # Check each block
            for i in range(1, len(st.session_state.bc.chain)):
                c, p = st.session_state.bc.chain[i], st.session_state.bc.chain[i-1]
                
                st.write(f"Checking block {i}...")
                
                # Check block hash
                if c.hash != c.compute_hash():
                    st.error(f"   - Block hash invalid: Content has been tampered with ❌")
                else:
                    st.success(f"   - Block hash valid ✅")
                
                # Check proof of work
                if not c.hash.startswith('0'*c.difficulty):
                    st.error(f"   - Proof-of-work invalid: Difficulty requirement not met ❌")
                else:
                    st.success(f"   - Proof-of-work valid ✅")
                
                # Check block linkage
                if c.prev_hash != p.hash:
                    st.error(f"   - Block linkage invalid: Previous hash doesn't match ❌")
                else:
                    st.success(f"   - Block linkage valid ✅")
                
                # Check vote signatures
                for j, vote in enumerate(c.encrypted_votes):
                    if isinstance(vote, dict):
                        try:
                            voter_id = st.session_state.bc.decrypt_vote(vote['encrypted_voter'])
                            candidate = st.session_state.bc.decrypt_vote(vote['encrypted_candidate'])
                            vote_data = f"{voter_id}|{candidate}|{vote['timestamp']}"
                            
                            if not st.session_state.bc.verify_signature(vote_data, bytes.fromhex(vote['signature'])):
                                st.error(f"   - Vote {j+1} signature invalid: Vote has been tampered with ❌")
                            else:
                                st.success(f"   - Vote {j+1} signature valid ✅")
                        except:
                            st.error(f"   - Error verifying vote {j+1} ❌")
    else:
        st.info(message)

# ---- Pending Votes ----
st.subheader("Pending Votes")
if st.session_state.bc.pending_votes:
    encrypted_data = []
    for vote in st.session_state.bc.pending_votes:
        encrypted_data.append({
            "Voter Hash": hashlib.sha256(vote['encrypted_voter'].encode()).hexdigest()[:16],
            "Signature": vote['signature'][:16] + "...",
            "Timestamp": vote['timestamp']
        })
    st.dataframe(encrypted_data)
else:
    st.info("No pending votes")

# ---- Blockchain ----
st.subheader("Blockchain")
for b in st.session_state.bc.chain:
    with st.expander(f"Block #{b.index} | Hash: {b.hash[:16]}..."):
        st.text(f"Previous Hash: {b.prev_hash[:16]}...")
        st.text(f"Nonce: {b.nonce}")
        st.text(f"Timestamp: {datetime.fromtimestamp(b.timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
        st.text("Votes:")
        
        if isinstance(b.encrypted_votes[0], dict):
            vote_data = []
            for vote in b.encrypted_votes:
                vote_data.append({
                    "Voter Hash": hashlib.sha256(vote['encrypted_voter'].encode()).hexdigest()[:16],
                    "Signature": vote['signature'][:16] + "...",
                    "Timestamp": vote['timestamp']
                })
            st.dataframe(vote_data)
        else:
            st.info(b.encrypted_votes[0])

# ---- Verification ----
st.subheader("Blockchain Verification")
if st.button("Verify Integrity"):
    ok, msg = st.session_state.bc.verify_integrity()
    if ok:
        st.success(msg)
    else:
        st.error(msg)

# ---- Results ----
st.subheader("Election Results")
res = st.session_state.bc.get_results()
if sum(res.values()) > 0:
    st.bar_chart(pd.DataFrame({"Candidates": list(res.keys()), "Votes": list(res.values())}).set_index("Candidates"))
    st.write("Detailed Results:")
    for candidate, votes in res.items():
        st.write(f"{candidate}: {votes} votes")
else:
    st.info("No votes cast yet")
