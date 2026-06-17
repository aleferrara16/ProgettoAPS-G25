"""
Benchmark esteso per raccogliere dati di scalabilità del sistema.
Produce risultati per diversi numeri di elettori.
"""
import time
import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.auth_server import AuthenticationServer
from app.core.client_wallet import ClientWallet
from app.core.bacheca import BulletinBoard
from app.core.urna import Urna

def benchmark_scale(num_votes):
    """Esegue un benchmark completo per un dato numero di voti."""
    auth_server = AuthenticationServer(bits=2048)
    pub_key = auth_server.get_public_key()
    bacheca = BulletinBoard()
    urna = Urna(pub_key, bacheca, num_trustees=3, quorum=2)
    
    wallet = ClientWallet(pub_key)
    
    # Blinding + Signing
    t0 = time.perf_counter()
    m_prime = wallet.generate_and_blind_token()
    t_blind = time.perf_counter() - t0
    
    t0 = time.perf_counter()
    s_prime = auth_server.sign_blind_token("10002345", m_prime)
    t_sign = time.perf_counter() - t0
    
    t0 = time.perf_counter()
    wallet.unblind_signature(s_prime)
    t_unblind = time.perf_counter() - t0
    
    # Cifratura singola
    t0 = time.perf_counter()
    C = wallet.create_encrypted_ballot("SI", urna.get_public_key(), simulate_jitter=False)
    t_encrypt = time.perf_counter() - t0
    
    packet_size = len(C)
    
    # Generazione massiva di voti
    t0 = time.perf_counter()
    for i in range(num_votes):
        urna.cast_vote(wallet.create_encrypted_ballot("SI", urna.get_public_key(), simulate_jitter=False))
    t_vote_gen = time.perf_counter() - t0
    
    # Scrutinio
    shares = urna.get_trustee_shares()[:2]
    t0 = time.perf_counter()
    urna.tally(shares)
    t_tally = time.perf_counter() - t0
    
    # Merkle Tree
    t0 = time.perf_counter()
    root = bacheca.build_merkle_tree()
    t_merkle_build = time.perf_counter() - t0
    
    token_hex = wallet.m_hex
    t0 = time.perf_counter()
    proof = bacheca.get_merkle_proof(token_hex)
    bacheca.verify_merkle_proof(token_hex, proof, root)
    t_merkle_verify = time.perf_counter() - t0
    
    return {
        "num_votes": num_votes,
        "blind_ms": round(t_blind * 1000, 2),
        "sign_ms": round(t_sign * 1000, 2),
        "unblind_ms": round(t_unblind * 1000, 2),
        "encrypt_ms": round(t_encrypt * 1000, 2),
        "packet_size_bytes": packet_size,
        "vote_gen_total_ms": round(t_vote_gen * 1000, 2),
        "vote_gen_avg_ms": round(t_vote_gen * 1000 / num_votes, 2),
        "tally_total_ms": round(t_tally * 1000, 2),
        "tally_avg_ms": round(t_tally * 1000 / num_votes, 2),
        "merkle_build_ms": round(t_merkle_build * 1000, 2),
        "merkle_verify_ms": round(t_merkle_verify * 1000, 2),
    }

if __name__ == "__main__":
    scales = [10, 50, 100, 500, 1000]
    print("=" * 80)
    print("BENCHMARK ESTESO - SCALABILITÀ DEL SISTEMA DI E-VOTING")
    print("=" * 80)
    
    results = []
    for n in scales:
        print(f"\nEsecuzione benchmark con {n} voti...")
        r = benchmark_scale(n)
        results.append(r)
        print(f"  Scrutinio: {r['tally_total_ms']} ms totale ({r['tally_avg_ms']} ms/voto)")
        print(f"  Merkle Build: {r['merkle_build_ms']} ms | Verify: {r['merkle_verify_ms']} ms")
    
    print("\n" + "=" * 80)
    print(f"{'N Voti':>8} | {'Scrutinio (ms)':>14} | {'ms/voto':>8} | {'Merkle Build':>12} | {'Merkle Verify':>13}")
    print("-" * 80)
    for r in results:
        print(f"{r['num_votes']:>8} | {r['tally_total_ms']:>14} | {r['tally_avg_ms']:>8} | {r['merkle_build_ms']:>12} | {r['merkle_verify_ms']:>13}")
    print("=" * 80)
