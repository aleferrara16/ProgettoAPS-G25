import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import json
import secrets
from app.core.auth_server import AuthenticationServer
from app.core.client_wallet import ClientWallet
from app.core.bacheca import BulletinBoard
from app.core.urna import Urna

def run_simulation():
    print("=" * 60)
    print("SIMULAZIONE COMPLETA DEL SISTEMA DI E-VOTO UNIVERSITARIO")
    print("Conforme alle specifiche del progetto APS-G25 (2026)")
    print("=" * 60)
    print()

    # 1. Inizializzazione dei server
    print("[1] INIZIALIZZAZIONE DELL'INFRASTRUTTURA")
    auth_server = AuthenticationServer(bits=2048)
    pub_key = auth_server.get_public_key()
    bacheca = BulletinBoard()
    urna = Urna(pub_key, bacheca, num_trustees=3, quorum=2)
    print("    - Generazione chiavi RSA a 2048 bit dell'Ateneo completata.")
    print("    - Generazione chiavi dell'Urna e Shamir Secret Sharing completati.")
    print("    - Bacheca pubblica e Urna inizializzate.")
    print()

    voters = [
        {"id": "10002345", "nome": "Mario Rossi", "choice": "SI"},
        {"id": "10005678", "nome": "Luigi Bianchi", "choice": "NO"},
        {"id": "10009101", "nome": "Anna Verdi", "choice": "SCHEDA_BIANCA"}
    ]

    print("[2] INIZIO SESSIONE DI VOTO REGOLARE")
    tokens_to_verify = [] 
    wallets = {}

    for voter in voters:
        print(f"\n---> Elettore: {voter['nome']} (Matricola: {voter['id']})")
        time.sleep(0.1)
        
        wallet = ClientWallet(pub_key)
        m_prime = wallet.generate_and_blind_token()
        print(f"    [Client] Generato gettone m e accecato m'.")
        
        print("    [SSO-Ateneo] Invio gettone accecato per firma...")
        s_prime = auth_server.sign_blind_token(voter["id"], m_prime)
        print(f"    [SSO-Ateneo] Matricola verificata, firma cieca s' emessa.")

        m_hex, s_hex = wallet.unblind_signature(s_prime)
        print(f"    [Client] Firma pulita estratta (unblinded s).")
        
        # Save wallet for coercion test later
        wallets[voter["id"]] = wallet
        
        # Per la simulazione di Anna (10009101), il primo voto è stato "costretto" a NO
        choice = "NO" if voter["id"] == "10009101" else voter["choice"]
        
        print(f"    [Client] Creazione payload JSON e cifratura ibrida AEAD...")
        C = wallet.create_encrypted_ballot(choice, urna.get_public_key(), simulate_jitter=True)
        
        print(f"    [Urna] Invio scheda cifrata (dimensione: {len(C)} byte)...")
        urna.cast_vote(C)
        print("    [Urna] Pacchetto ricevuto e accodato (non decifrato).")
        tokens_to_verify.append((voter["nome"], m_hex, voter["choice"]))
            
    print("\n" + "=" * 60)
    
    print("[3] TENTATIVI DI ATTACCO E CONTROMISURE DI SICUREZZA")
    
    print("\n* Attacco A: Tentativo di Double Voting all'Authentication Server (TM.1)")
    wallet_malicious = ClientWallet(pub_key)
    m_prime_malicious = wallet_malicious.generate_and_blind_token()
    try:
        auth_server.sign_blind_token("10002345", m_prime_malicious)
    except ValueError as e:
        print(f"  [SUCCESSO SICUREZZA] Server ha respinto la richiesta: {e}")

    print("\n* Attacco B: Coercizione e Receipt-Freeness (TM.4 e TM.2)")
    print("  Simuliamo che Anna Verdi (10009101) sia stata costretta a votare 'NO' prima.")
    print("  Ora vota liberamente 'SCHEDA_BIANCA' (che era la sua vera intenzione).")
    wallet_anna = wallets["10009101"]
    
    time.sleep(0.1) # Simula passaggio di tempo affinché il timestamp sia maggiore
    
    C_free = wallet_anna.create_encrypted_ballot("SCHEDA_BIANCA", urna.get_public_key(), simulate_jitter=False)
    urna.cast_vote(C_free)
    print("  [Urna] Il voto libero (più recente) è stato inviato all'Urna usando lo STESSO gettone m.")
    print("  [Urna] La deduplicazione scarterà il voto coercizzato 'NO' allo scrutinio.")

    print("\n* Attacco C: Voto con payload malformato o cifratura errata")
    fake_payload = secrets.token_bytes(300)
    urna.cast_vote(fake_payload)
    print("  [Urna] Pacchetto malformato accodato (verrà scartato durante lo scrutinio).")

    print("\n" + "=" * 60)

    print("[4] CHIUSURA URNE E SCRUTINIO CON QUORUM (SHAMIR)")
    print("  La commissione presenta 2 quote su 3 per ricostruire la chiave dell'Urna.")
    shares = urna.get_trustee_shares()[:2]
    
    try:
        tally = urna.tally(shares)
        print("  [SUCCESSO] Chiave ricostruita! Voti decifrati e deduplicati.")
        print("\n  Risultato finale dello Scrutinio:")
        for opzione, voti in tally.items():
            print(f"  - {opzione}: {voti}")
    except ValueError as e:
        print(f"  [ERRORE SCRUTINIO] {e}")

    print("\n" + "=" * 60)

    print("[5] AUDIT E VERIFICA IN BACHECA PUBBLICA (MERKLE TREE)")
    root = bacheca.get_merkle_root()
    print(f"  Merkle Root dell'elezione: {root}")
    print()
    
    for nome, token, scelta in tokens_to_verify:
        voto_registrato = bacheca.get_vote(token)
        proof = bacheca.get_merkle_proof(token)
        is_valid = bacheca.verify_merkle_proof(token, proof, root) if proof else False
        status = "CORRETTO (Verificato)" if voto_registrato == scelta and is_valid else "ERRATO/NON VERIFICATO"
        print(f"  - Elettore: {nome}")
        print(f"    Gettone segreto: {token}")
        print(f"    Preferenza espressa: {scelta} | Esito: {status}")
        
    print("\n" + "=" * 60)
    print("SIMULAZIONE TERMINATA CON SUCCESSO")
    print("=" * 60)

if __name__ == "__main__":
    run_simulation()

