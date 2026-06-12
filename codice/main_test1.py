from auth_server import AuthenticationServer
from client_wallet import ClientWallet
import hashlib
from Crypto.Util.number import bytes_to_long

def run_simulation():
    print("=== 1. INIZIALIZZAZIONE INFRASTRUTTURA ATENEO ===")
    server = AuthenticationServer(bits=2048)
    ateneo_pub_key = server.get_public_key()
    print(f"Chiave pubblica Ateneo generata correttamente. Modulo n: {hex(ateneo_pub_key[1])[:30]}...\n")

    print("=== 2. ACCESSO STUDENTE E GENERAZIONE GETTONE CIECO ===")
    studente = ClientWallet(ateneo_pub_key)
    student_id = "10002345"
    
    m_prime = studente.generate_and_blind_token()
    print(f"Gettone accecato generato lato client (m'): {hex(m_prime)[:30]}...\n")

    print("=== 3. TRASMISSIONE ED EMISSIONE FIRMA CIECA ===")
    try:
        s_prime = server.sign_blind_token(student_id, m_prime)
        print(f"Il server ha autenticato la matricola {student_id} e applicato la firma cieca.")
        print(f"Firma Cieca (s'): {hex(s_prime)[:30]}...\n")
    except ValueError as e:
        print(f"Errore di autenticazione: {e}")
        return

    print("=== 4. ESTRAZIONE CREDENZIALE ANONIMA LATO CLIENT ===")
    gettone_m, firma_s = studente.unblind_signature(s_prime)
    print(f"Unaligned completato con successo.")
    print(f"Gettone finale in chiaro (m): {gettone_m}")
    print(f"Firma finale in chiaro (s): {firma_s[:30]}...\n")

    print("=== 5. AUDIT DI VERIFICA DELLA CREDENZIALE (WP2.2, PASSO 3) ===")
    # Chiunque può verificare la validità di (m, s) usando solo la chiave pubblica dell'Ateneo
    e, n = ateneo_pub_key
    m_bytes = bytes.fromhex(gettone_m)
    
    # Calcola H(m) nello stesso modo del client
    h = hashlib.sha256(m_bytes).digest()
    hm_atteso = bytes_to_long(h) % n
    
    # Verifica l'uguaglianza s^e == H(m) mod n
    s_int = int(firma_s, 16)
    valore_verificato = pow(s_int, e, n)
    
    print(f"Valore decifrato da s^e mod n: {hex(valore_verificato)[:30]}...")
    print(f"Valore atteso da H(m):          {hex(hm_atteso)[:30]}...")
    
    if valore_verificato == hm_atteso:
        print("\n[SUCCESS] La credenziale è crittograficamente valida! Anonimato garantito.")
    else:
        print("\n[FAILURE] Errore matematico nel protocollo di unblinding.")

if __name__ == "__main__":
    run_simulation()