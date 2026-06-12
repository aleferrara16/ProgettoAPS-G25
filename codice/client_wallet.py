import secrets
import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse

class ClientWallet:
    def __init__(self, ateneo_pub_key):
        self.e, self.n = ateneo_pub_key
        self.m = None
        self.r = None

    def _full_domain_hash(self, message_bytes):
        """
        Mappa il gettone m sul dominio RSA (RSA-FDH) tramite hashing SHA-256 riprodotto.
        Previene attacchi omomorfici ed esistenziali del Textbook RSA (§2.2).
        """
        # Semplificazione accademica sicura di FDH: eseguiamo l'hash del gettone
        # e ci assicuriamo che sia matematicamente minore del modulo RSA 'n'
        h = hashlib.sha256(message_bytes).digest()
        h_int = bytes_to_long(h)
        return h_int % self.n

    def generate_and_blind_token(self):
        """
        Genera il gettone segreto m e calcola il valore accecato m'.
        Corrisponde alla fase 2.2 (Generazione e Blinding) del WP2.
        """
        # 1. Generazione gettone pseudocasuale sicuro a 128-bit (CSPRNG)
        self.m = secrets.token_bytes(16) # m in {0,1}^128
        
        # 2. Computazione dell'FDH del gettone: H(m)
        hm = self._full_domain_hash(self.m)
        
        # 3. Selezione del fattore di accecamento casuale r in Z*_n
        while True:
            self.r = secrets.randbelow(self.n)
            if self.r > 1 and hashlib.blake2b(long_to_bytes(self.r)).digest() != b'' and math_gcd(self.r, self.n) == 1:
                break
                
        # 4. Calcolo del gettone accecato: m' = H(m) * r^e mod n
        r_pow_e = pow(self.r, self.e, self.n)
        m_prime = (hm * r_pow_e) % self.n
        return m_prime

    def unblind_signature(self, s_prime):
        """
        Rimuove il fattore di accecamento per estrarre la credenziale in chiaro.
        Corrisponde alla fase 2.2 (Unblinding) del WP2.
        """
        # Calcolo dell'inverso modulare di r: r^-1 mod n
        r_inv = inverse(self.r, self.n)
        
        # Estrazione della firma pulita s = s' * r^-1 mod n
        s = (s_prime * r_inv) % self.n
        
        # Ritorna la coppia (m, s) in formato esadecimale pronto per la scheda JSON (§2.3.1)
        return self.m.hex(), hex(s)

def math_gcd(a, b):
    while b:
        a, b = b, a % b
    return a