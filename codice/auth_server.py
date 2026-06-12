import hashlib
from Crypto.Util.number import getPrime, inverse

class AuthenticationServer:
    def __init__(self, bits=2048):
        # Generazione delle chiavi RSA stabili dell'Ateneo (simulazione HSM)
        self.p = getPrime(bits // 2)
        self.q = getPrime(bits // 2)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = 65537
        self.d = inverse(self.e, self.phi)
        
        # Database dello stato degli aventi diritto
        # Struttura: { matricola: has_voted (bool) }
        self.voter_registry = {
            "10002345": False,
            "10005678": False,
            "10009101": False
        }

    def get_public_key(self):
        """Rilascia la chiave pubblica dell'Ateneo (e, n)."""
        return self.e, self.n

    def sign_blind_token(self, student_id, m_prime):
        """
        Valida l'identità dell'elettore via SSO e appone la firma cieca.
        Corrisponde alla fase 2.2 (Signing) del WP2.
        """
        if student_id not in self.voter_registry:
            raise ValueError("Identità civile non censita tra gli aventi diritto.")
            
        if self.voter_registry[student_id]:
            raise ValueError("Tentativo di Double Voting rilevato (TM.1). Gettoni già emessi.")

        # Transizione di stato atomica: l'utente ha ritirato il diritto di voto
        self.voter_registry[student_id] = True
        
        # Calcolo della firma cieca: s' = (m')^d mod n
        s_prime = pow(m_prime, self.d, self.n)
        return s_prime