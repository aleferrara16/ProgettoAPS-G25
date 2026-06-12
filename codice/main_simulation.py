import sys
import time
from auth_server import AuthenticationServer
from client_wallet import ClientWallet
from bacheca import BulletinBoard
from urna import Urna

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
    urna = Urna(pub_key, bacheca)
    print("    - Generazione chiavi RSA a 2048 bit dell'Ateneo completata.")
    print(f"    - Modulo RSA n (primi 32 byte): {hex(pub_key[1])[:64]}...")
    print("    - Bacheca pubblica e Urna inizializzate.")
    print()

    # Database degli studenti registrati nell'Auth Server
    voters = [
        {"id": "10002345", "nome": "Mario Rossi", "choice": "SI"},
        {"id": "10005678", "nome": "Luigi Bianchi", "choice": "NO"},
        {"id": "10009101", "nome": "Anna Verdi", "choice": "SCHEDA_BIANCA"}
    ]

    # 2. Processo di voto regolare per 3 elettori
    print("[2] INIZIO SESSIONE DI VOTO REGOLARE")
    tokens_to_verify = [] # Per simulare il controllo in bacheca a fine voto

    for voter in voters:
        print(f"\n---> Elettore: {voter['nome']} (Matricola: {voter['id']})")
        time.sleep(0.1)
        
        # Lato Elettore (Client)
        wallet = ClientWallet(pub_key)
        m_prime = wallet.generate_and_blind_token()
        print(f"    [Client] Generato gettone m segreto e accecato m' (primi 16 byte): {hex(m_prime)[:34]}...")
        
        # Fase di Autenticazione ed Emissione Firma Cieca (SSO)
        print("    [SSO-Ateneo] Invio gettone accecato per firma...")
        try:
            s_prime = auth_server.sign_blind_token(voter["id"], m_prime)
            print(f"    [SSO-Ateneo] Matricola verificata, firma cieca s' emessa.")
        except Exception as e:
            print(f"    [ERRORE SSO] {e}")
            continue

        # Unblinding lato Client
        m_hex, s_hex = wallet.unblind_signature(s_prime)
        print(f"    [Client] Firma pulita estratta (unblinded s).")
        print(f"             Gettone finale m (hex): {m_hex}")
        print(f"             Firma s (primi 16 byte): {s_hex[:34]}...")
        
        # Invio voto all'Urna (Anonimo!)
        print(f"    [Urna] Invio scheda anonima: (gettone, firma, preferenza={voter['choice']})...")
        try:
            urna.cast_vote(m_hex, s_hex, voter["choice"])
            print("    [Urna] Firma verificata ed accettata. Voto registrato!")
            # Salviamo il gettone per l'audit successivo dell'elettore
            tokens_to_verify.append((voter["nome"], m_hex, voter["choice"]))
        except Exception as e:
            print(f"    [ERRORE URNA] {e}")
            
    print("\n" + "=" * 60)
    
    # 3. Tentativi di attacco e test delle contromisure di sicurezza
    print("[3] TENTATIVI DI ATTACCO E CONTROMISURE DI SICUREZZA")
    
    # Attacco A: Double Voting presso l'Auth Server (TM.1)
    # Mario Rossi prova a richiedere un secondo gettone firmato
    print("\n* Attacco A: Tentativo di Double Voting all'Authentication Server (SSO)")
    print("  Mario Rossi (10002345) prova ad autenticarsi nuovamente per ritirare un altro gettone.")
    wallet_malicious = ClientWallet(pub_key)
    m_prime_malicious = wallet_malicious.generate_and_blind_token()
    try:
        auth_server.sign_blind_token("10002345", m_prime_malicious)
        print("  [FALLIMENTO SICUREZZA] Il server ha emesso un secondo gettone!")
    except ValueError as e:
        print(f"  [SUCCESSO SICUREZZA] Server ha respinto la richiesta: {e}")

    # Attacco B: Double Voting presso l'Urna (TM.2)
    # Ripresentiamo lo stesso gettone registrato da Mario Rossi (il primo della nostra lista)
    print("\n* Attacco B: Tentativo di Double Voting all'Urna")
    nome, m_rossi, scelta_rossi = tokens_to_verify[0]
    # Recuperiamo la firma originaria dal wallet simulato per ripetere il voto
    print(f"  Un utente prova a inviare nuovamente il gettone di {nome} ({m_rossi}) con voto 'NO'.")
    # Troviamo la firma originale
    # Per semplicità, creiamo un wallet ad-hoc e proviamo a inviare nuovamente
    try:
        # Recuperiamo la prima firma unblinded (avendo m_rossi e una firma valida per esso)
        # s_hex della prima transazione è valido, proviamo a riutilizzarlo
        # Per scopi di simulazione, usiamo le stesse credenziali già usate
        # Recuperiamo s_hex dal database dei voti dell'urna (usiamo quella valida)
        # Siccome non l'abbiamo salvata globalmente, creiamo una simulazione del pacchetto riutilizzato
        # useremo i valori corretti salvati per il primo studente
        pass
    except:
        pass
    
    # Eseguiamo il test effettivo sul set locale dei gettoni
    try:
        # Proviamo a chiamare cast_vote con lo stesso gettone m_rossi
        # Recuperiamo la firma valida s_hex generata prima per m_rossi.
        # Creiamo un wallet temporaneo che rifà lo stesso giro per Mario Rossi, ma invia due volte.
        w_tmp = ClientWallet(pub_key)
        mp = w_tmp.generate_and_blind_token()
        # Per simulare correttamente, registriamo un utente temporaneo fittizio
        # o resettiamo lo stato di un utente per farlo firmare
        auth_server.voter_registry["10002345"] = False # Resettiamo temporaneamente per fargli firmare
        sp = auth_server.sign_blind_token("10002345", mp)
        m_h, s_h = w_tmp.unblind_signature(sp)
        
        # Voto 1
        urna.cast_vote(m_h, s_h, "SI")
        print("  [Urna] Primo voto del gettone accettato.")
        # Voto 2 (Double Voting)
        urna.cast_vote(m_h, s_h, "NO")
        print("  [FALLIMENTO SICUREZZA] L'Urna ha accettato due volte lo stesso gettone!")
    except ValueError as e:
        print(f"  [SUCCESSO SICUREZZA] L'Urna ha respinto il secondo voto: {e}")

    # Attacco C: Voto con Gettone non firmato o firma contraffatta
    print("\n* Attacco C: Tentativo di voto con gettone non autorizzato (firma falsa)")
    import secrets
    m_fake_hex = secrets.token_bytes(16).hex()
    fake_sig_hex = hex(1234567890) # Firma falsa
    try:
        urna.cast_vote(m_fake_hex, fake_sig_hex, "SI")
        print("  [FALLIMENTO SICUREZZA] L'Urna ha accettato una firma fasulla!")
    except ValueError as e:
        print(f"  [SUCCESSO SICUREZZA] L'Urna ha respinto il gettone non firmato: {e}")

    print("\n" + "=" * 60)

    # 4. Controllo in bacheca (Audit ed Elettore)
    print("[4] AUDIT E VERIFICA IN BACHECA PUBBLICA (Receipt-Freeness & Verificabilità)")
    print("Ogni elettore può controllare che il suo gettone segreto sia presente in Bacheca")
    print("con la preferenza espressa, ma nessuno può risalire alla sua identità civile.")
    print()
    
    for nome, token, scelta in tokens_to_verify:
        voto_registrato = bacheca.get_vote(token)
        status = "CORRETTO" if voto_registrato == scelta else "ERRATO"
        print(f"  - Elettore: {nome}")
        print(f"    Gettone segreto: {token}")
        print(f"    Preferenza espressa: {scelta} | Registrata: {voto_registrato} -> {status}")
        
    print()
    
    # 5. Scrutinio finale dei voti
    print("[5] SCRUTINIO FINALE")
    tally = urna.get_tally()
    print("    Tutti i voti sono stati scrutinati direttamente dalla Bacheca pubblica:")
    for opzione, voti in tally.items():
        print(f"    - Opzione '{opzione}': {voti} voti")
        
    print("\n" + "=" * 60)
    print("SIMULAZIONE TERMINATA CON SUCCESSO")
    print("=" * 60)

if __name__ == "__main__":
    run_simulation()
