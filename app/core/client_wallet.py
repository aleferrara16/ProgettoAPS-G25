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
        # spacchettiamo la chiave pubblica dell'ateneo
        self.e, self.n = ateneo_pub_key
        self.m = None
        self.r = None
        self.m_hex = None
        self.s_hex = None

    def _full_domain_hash(self, message_bytes):
        """
        Mappa il gettone sul dominio RSA con un hash iterativo tipo MGF1.
        Ci serve per evitare i soliti problemi del textbook RSA (attacchi omomorfici ecc).
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
        Crea il gettone random e lo "acceca" (blinding) prima di mandarlo al server.
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
        Toglie il blinding factor (r) per ottenere la firma pulita sulla nostra credenziale.
        """
        # usiamo pow per l'inverso modulare (va bene da python 3.8 in su)
        r_inv = pow(self.r, -1, self.n)
        s = (s_prime * r_inv) % self.n
        self.m_hex = self.m.hex()
        self.s_hex = hex(s)
        return self.m_hex, self.s_hex

    def create_encrypted_ballot(self, preference, PK_urna, simulate_jitter=True):
        """
        Prepara il JSON della scheda, calcola l'hash di binding e cifra tutto.
        """
        if simulate_jitter:
            pass # TODO: aggiungere un po' di ritardo random prima di inviare (jitter)
            
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
        
        # Prepariamo la cifratura ibrida
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
        # cryptography accorpa testo cifrato e tag di autenticazione
        csym_and_tau = aesgcm.encrypt(iv, payload_bytes, ckey) # AAD = ckey
        
        # Assembliamo il pacchettone finale (IV + Chiave cifrata + Payload cifrato)
        C = iv + ckey + csym_and_tau
        return C