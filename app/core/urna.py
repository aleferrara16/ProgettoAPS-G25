import hashlib
import json
import secrets
import random

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Costanti per Shamir Secret Sharing su campo finito
PRIME = 2**256 + 297

def _eval_poly(poly, x, p):
    res = 0
    for coeff in reversed(poly):
        res = (res * x + coeff) % p
    return res

def split_secret(secret, quorum, num_trustees):
    """Suddivide il segreto in quote valutando un polinomio casuale."""
    poly = [secret] + [secrets.randbelow(PRIME) for _ in range(quorum - 1)]
    shares = []
    for i in range(1, num_trustees + 1):
        shares.append((i, _eval_poly(poly, i, PRIME)))
    return shares

def combine_shares(shares):
    """Ricostruisce il segreto tramite interpolazione di Lagrange in x=0."""
    secret = 0
    for j, (xj, yj) in enumerate(shares):
        num = 1
        den = 1
        for m, (xm, ym) in enumerate(shares):
            if j != m:
                num = (num * (-xm)) % PRIME
                den = (den * (xj - xm)) % PRIME
        # pow(den, -1, PRIME) in Python 3.8+ calcola l'inverso modulare
        lagrange = (yj * num * pow(den, -1, PRIME)) % PRIME
        secret = (secret + lagrange) % PRIME
    return secret

class Urna:
    def __init__(self, ateneo_pub_key, bacheca, num_trustees=3, quorum=2):
        """
        Inizializza l'Urna con la chiave pubblica dell'Ateneo per la verifica 
        delle firme cieche e il riferimento alla Bacheca pubblica.
        Implementa la generazione della chiave di Urna e Shamir Secret Sharing.
        """
        self.e, self.n = ateneo_pub_key
        self.bacheca = bacheca
        self.valid_preferences = {"SI", "NO", "SCHEDA_BIANCA", "NULLA"}
        
        # 1. Setup Chiave dell'Urna e Shamir Secret Sharing
        urna_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.PK_urna = urna_key.public_key()
        
        self.master_key = secrets.token_bytes(32)
        master_key_int = int.from_bytes(self.master_key, 'big')
        self.trustee_shares = split_secret(master_key_int, quorum, num_trustees)
        
        # Cifriamo la chiave privata RSA dell'Urna con la master_key
        sk_bytes = urna_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        aesgcm = AESGCM(self.master_key)
        self.sk_nonce = secrets.token_bytes(12)
        self.sk_ciphertext = aesgcm.encrypt(self.sk_nonce, sk_bytes, b"")
        
        # L'urna dimentica il segreto (simulazione)
        urna_key = None
        self.master_key = None
        
        # Stato dell'elezione
        self.is_closed = False
        
        # Batch dei pacchetti cifrati
        self.encrypted_batch = []

    def get_public_key(self):
        return self.PK_urna

    def get_trustee_shares(self):
        return self.trustee_shares

    def _full_domain_hash(self, message_bytes):
        target_len = (self.n.bit_length() + 7) // 8
        T = b""
        counter = 0
        while len(T) < target_len:
            C = counter.to_bytes(4, 'big')
            T += hashlib.sha256(message_bytes + C).digest()
            counter += 1
        return int.from_bytes(T[:target_len], 'big') % self.n

    def verify_signature(self, gettone_m_hex, signature_s_hex):
        """
        Verifica la validità crittografica della firma s sul gettone m.
        """
        try:
            m_bytes = bytes.fromhex(gettone_m_hex)
            s_int = int(signature_s_hex, 16)
            
            # Calcolo H(m) mod n (RSA-FDH locale espanso)
            hm_atteso = self._full_domain_hash(m_bytes)
            valore_verificato = pow(s_int, self.e, self.n)
            
            return valore_verificato == hm_atteso
        except Exception:
            return False

    def cast_vote(self, C):
        """
        Riceve il pacchetto cifrato C = (iv || Ckey || csym_and_tau) e lo mette in coda.
        Nessuna decifratura viene eseguita qui, garantendo l'anonimato fino allo scrutinio.
        """
        if self.is_closed:
            raise ValueError("Le urne sono chiuse. Impossibile accettare nuovi voti.")
            
        self.encrypted_batch.append(C)
        return hashlib.sha256(C).hexdigest()

    def tally(self, presented_shares):
        """
        Esegue lo scrutinio: chiude le urne, ricostruisce la chiave, decifra, deduplica e somma.
        """
        # Chiudiamo le urne: da questo momento non si accettano più voti
        self.is_closed = True
        
        # 1. Ricostruzione del segreto
        try:
            master_key_int = combine_shares(presented_shares)
            master_key = master_key_int.to_bytes(32, 'big')
            
            aesgcm = AESGCM(master_key)
            sk_bytes = aesgcm.decrypt(self.sk_nonce, self.sk_ciphertext, b"")
            sk_urna = serialization.load_pem_private_key(sk_bytes, password=None)
        except Exception as e:
            raise ValueError("Ricostruzione della chiave fallita. Quorum non raggiunto o quote invalide.")

        valid_votes = {} # { gettone_m : (timestamp, preferenza) }
        
        # Shuffling dei pacchetti (WP2 §2.4)
        random.shuffle(self.encrypted_batch)
        
        # 2. Decifratura e Validazione
        for C in self.encrypted_batch:
            try:
                # Estrazione componenti: iv (12 bytes), Ckey (256 bytes per RSA 2048), csym_and_tau (resto)
                iv = C[:12]
                ckey = C[12:12+256]
                csym_and_tau = C[12+256:]
                
                # Decapsulamento chiave simmetrica
                ksym = sk_urna.decrypt(
                    ckey,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decifratura payload (AEAD)
                aesgcm_payload = AESGCM(ksym)
                payload = aesgcm_payload.decrypt(iv, csym_and_tau, ckey) # AAD = ckey
                
                data = json.loads(payload.decode())
                pref = data['preferenza']
                m_hex = data['gettone_m']
                s_hex = data['firma_s']
                ts = data['timestamp']
                h_bind = data['h_bind']
                
                # Validazione
                if pref not in self.valid_preferences:
                    continue
                    
                if not self.verify_signature(m_hex, s_hex):
                    continue
                    
                # Verifica h_bind
                expected_bind = hashlib.sha256(f"{pref}{m_hex}{ts}".encode()).hexdigest()
                if h_bind != expected_bind:
                    continue
                    
                # Deduplicazione posticipata per Receipt-Freeness
                if m_hex in valid_votes:
                    old_ts, _ = valid_votes[m_hex]
                    if ts > old_ts: # Tieni il più recente
                        valid_votes[m_hex] = (ts, pref)
                else:
                    valid_votes[m_hex] = (ts, pref)
                    
            except Exception as e:
                # Scarta pacchetti malformati o alterati
                continue

        # 3. Aggregazione e popolamento Bacheca
        tally_results = {p: 0 for p in self.valid_preferences}
        for m_hex, (ts, pref) in valid_votes.items():
            self.bacheca.add_vote(m_hex, pref)
            tally_results[pref] += 1
            
        # Costruisce il Merkle tree
        root = self.bacheca.build_merkle_tree()
        if root:
            # La commissione firma la Merkle Root a garanzia
            signature = sk_urna.sign(
                root.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.bacheca.set_root_signature(signature.hex())
            
        return tally_results
