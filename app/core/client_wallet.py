import secrets
import hashlib
import json
import math
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class ClientWallet:
    def __init__(self, ateneo_pub_key):
        # ateneo_pub_key is a tuple (e, n)
        self.e, self.n = ateneo_pub_key
        self.m = None
        self.r = None
        self.m_hex = None
        self.s_hex = None

    def _full_domain_hash(self, message_bytes):
        """
        Mappa il gettone m sul dominio RSA (RSA-FDH) tramite hash iterativo (MGF1-like)
        Previene attacchi omomorfici ed esistenziali del Textbook RSA (§2.2).
        """
        target_len = (self.n.bit_length() + 7) // 8
        T = b""
        counter = 0
        while len(T) < target_len:
            C = counter.to_bytes(4, 'big')
            T += hashlib.sha256(message_bytes + C).digest()
            counter += 1
        h_int = int.from_bytes(T[:target_len], 'big')
        return h_int % self.n

    def generate_and_blind_token(self):
        """
        Genera il gettone segreto m e calcola il valore accecato m'.
        Corrisponde alla fase 2.2 (Generazione e Blinding) del WP2.
        """
        self.m = secrets.token_bytes(16) 
        hm = self._full_domain_hash(self.m)
        while True:
            self.r = secrets.randbelow(self.n)
            if self.r > 1 and math.gcd(self.r, self.n) == 1:
                break
        r_pow_e = pow(self.r, self.e, self.n)
        m_prime = (hm * r_pow_e) % self.n
        return m_prime

    def unblind_signature(self, s_prime):
        """
        Rimuove il fattore di accecamento per estrarre la credenziale in chiaro.
        Corrisponde alla fase 2.2 (Unblinding) del WP2.
        """
        # Pow(r, -1, n) requires python 3.8+
        r_inv = pow(self.r, -1, self.n)
        s = (s_prime * r_inv) % self.n
        self.m_hex = self.m.hex()
        self.s_hex = hex(s)
        return self.m_hex, self.s_hex

    def create_encrypted_ballot(self, preference, PK_urna, simulate_jitter=True):
        """
        Crea la scheda JSON, calcola l'h_bind, e cifra tutto in modo ibrido (AEAD).
        PK_urna è un oggetto rsa.RSAPublicKey
        """
        if simulate_jitter:
            pass # Il jitter reale viene eseguito lato client-side
            
        ts = datetime.now(timezone.utc).isoformat()
        h_bind = hashlib.sha256(f"{preference}{self.m_hex}{ts}".encode()).hexdigest()
        
        payload_dict = {
            "preferenza": preference,
            "gettone_m": self.m_hex,
            "firma_s": self.s_hex,
            "timestamp": ts,
            "h_bind": h_bind
        }
        
        payload_bytes = json.dumps(payload_dict).encode()
        
        # Cifratura Ibrida KEM/DEM (WP2 2.3.2)
        ksym = secrets.token_bytes(32) # AES-256
        iv = secrets.token_bytes(12)   # GCM nonce
        
        # Cifratura RSA-OAEP della chiave simmetrica
        ckey = PK_urna.encrypt(
            ksym,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Cifratura AES-GCM del payload
        aesgcm = AESGCM(ksym)
        # La libreria cryptography gestisce (csym || tau) assieme come ciphertext
        csym_and_tau = aesgcm.encrypt(iv, payload_bytes, ckey) # AAD = ckey
        
        # Formato finale C = iv || ckey || csym_and_tau
        C = iv + ckey + csym_and_tau
        return C