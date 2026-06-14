import time
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.auth_server import AuthenticationServer
from app.core.client_wallet import ClientWallet
from app.core.bacheca import BulletinBoard
from app.core.urna import Urna

def benchmark():
    print("="*60)
    print("WP4: BENCHMARK E PRESTAZIONI DEL SISTEMA")
    print("="*60)
    
    # 1. Generazione Chiavi
    t0 = time.perf_counter()
    auth_server = AuthenticationServer(bits=2048)
    ateneo_pub_key = auth_server.get_public_key()
    t1 = time.perf_counter()
    print(f"Tempo generazione chiavi RSA Ateneo (2048 bit): {(t1-t0)*1000:.2f} ms")

    t0 = time.perf_counter()
    bacheca = BulletinBoard()
    urna = Urna(ateneo_pub_key, bacheca, num_trustees=3, quorum=2)
    t1 = time.perf_counter()
    print(f"Tempo generazione chiavi Urna + Shamir Secret Sharing: {(t1-t0)*1000:.2f} ms")
    
    # 2. Ciclo di Voto e Blind Signature
    wallet = ClientWallet(ateneo_pub_key)
    
    t0 = time.perf_counter()
    m_prime = wallet.generate_and_blind_token()
    t1 = time.perf_counter()
    print(f"Tempo Blinding lato client: {(t1-t0)*1000:.2f} ms")
    
    t0 = time.perf_counter()
    s_prime = auth_server.sign_blind_token("10002345", m_prime)
    t1 = time.perf_counter()
    print(f"Tempo Signing cieco (Ateneo): {(t1-t0)*1000:.2f} ms")
    
    t0 = time.perf_counter()
    wallet.unblind_signature(s_prime)
    t1 = time.perf_counter()
    print(f"Tempo Unblinding lato client: {(t1-t0)*1000:.2f} ms")

    # 3. Cifratura Scheda
    t0 = time.perf_counter()
    C = wallet.create_encrypted_ballot("SI", urna.get_public_key(), simulate_jitter=False)
    t1 = time.perf_counter()
    print(f"Tempo Cifratura Ibrida (RSA-OAEP + AES-GCM): {(t1-t0)*1000:.2f} ms")
    print(f"Dimensione pacchetto cifrato scambiato: {len(C)} bytes")
    
    # 4. Scrutinio massivo
    NUM_VOTES = 100
    print(f"\nGenerazione di {NUM_VOTES} voti cifrati per test di scrutinio...")
    for i in range(NUM_VOTES):
        urna.cast_vote(wallet.create_encrypted_ballot("NO", urna.get_public_key(), simulate_jitter=False))
        
    shares = urna.get_trustee_shares()[:2]
    
    t0 = time.perf_counter()
    urna.tally(shares)
    t1 = time.perf_counter()
    print(f"Tempo Scrutinio ({NUM_VOTES} voti): {(t1-t0)*1000:.2f} ms (media {(t1-t0)*1000/NUM_VOTES:.2f} ms/voto)")
    
    # 5. Merkle Tree
    t0 = time.perf_counter()
    root = bacheca.build_merkle_tree()
    t1 = time.perf_counter()
    print(f"Tempo costruzione Merkle Tree ({NUM_VOTES} foglie): {(t1-t0)*1000:.2f} ms")
    
    token_hex = wallet.m_hex
    t0 = time.perf_counter()
    proof = bacheca.get_merkle_proof(token_hex)
    bacheca.verify_merkle_proof(token_hex, proof, root)
    t1 = time.perf_counter()
    print(f"Tempo get/verify Merkle Proof: {(t1-t0)*1000:.2f} ms")
    
    print("="*60)

if __name__ == "__main__":
    benchmark()
