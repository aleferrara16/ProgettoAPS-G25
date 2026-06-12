import secrets
import hashlib
import json
import time
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

class ClientWallet:
    def __init__(self, ateneo_pub_key):
        self.e, self.n = ateneo_pub_key
        self.m = None
        self.r = None
        self.m_hex = None
        self.s_hex = None

    def _full_domain_hash(self, message_bytes):
        """
        Mappa il gettone m sul dominio RSA (RSA-FDH) tramite hashing SHA-256 riprodotto.
        Previene attacchi omomorfici ed esistenziali del Textbook RSA (§2.2).
        """
        h = hashlib.sha256(message_bytes).digest()
        h_int = bytes_to_long(h)
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
            if self.r > 1 and hashlib.blake2b(long_to_bytes(self.r)).digest() != b'' and math_gcd(self.r, self.n) == 1:
                break
        r_pow_e = pow(self.r, self.e, self.n)
        m_prime = (hm * r_pow_e) % self.n
        return m_prime

    def unblind_signature(self, s_prime):
        """
        Rimuove il fattore di accecamento per estrarre la credenziale in chiaro.
        Corrisponde alla fase 2.2 (Unblinding) del WP2.
        """
        r_inv = inverse(self.r, self.n)
        s = (s_prime * r_inv) % self.n
        self.m_hex = self.m.hex()
        self.s_hex = hex(s)
        return self.m_hex, self.s_hex

    def create_encrypted_ballot(self, preference, PK_urna, simulate_jitter=True):
        """
        Crea la scheda JSON, calcola l'h_bind, e cifra tutto in modo ibrido (AEAD).
        """
        if simulate_jitter:
            # Jittering simulato per mitigare attacchi di temporizzazione (Timing Attacks)
            time.sleep(0.01)
            
        ts = int(time.time() * 1000) # timestamp in millisecondi
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
        
        cipher_rsa = PKCS1_OAEP.new(PK_urna)
        ckey = cipher_rsa.encrypt(ksym)
        
        cipher_aes = AES.new(ksym, AES.MODE_GCM, nonce=iv)
        cipher_aes.update(ckey) # AAD
        csym, tau = cipher_aes.encrypt_and_digest(payload_bytes)
        
        # Formato finale C = iv || ckey || csym || tau
        C = iv + ckey + csym + tau
        return C

def math_gcd(a, b):
    while b:
        a, b = b, a % b
    return a