from cryptography.hazmat.primitives.asymmetric import rsa

class AuthenticationServer:
    def __init__(self, bits=2048):
        # Chiavi RSA dell'ateneo. Qua simuliamo un HSM in memoria.
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits
        )
        priv_numbers = self.private_key.private_numbers()
        self.d = priv_numbers.d
        self.n = priv_numbers.public_numbers.n
        self.e = priv_numbers.public_numbers.e
        
        # Dizionario per tenere traccia di chi ha già votato
        # Chiave: matricola, Valore: bool
        self.voter_registry = {
            "10002345": False,
            "10005678": False,
            "10009101": False
        }

    def get_public_key(self):
        """Restituisce la chiave pubblica (e, n)"""
        return self.e, self.n

    def sign_blind_token(self, student_id, m_prime):
        """
        Controlla se l'elettore può votare e applica la firma cieca.
        """
        if student_id not in self.voter_registry:
            raise ValueError("Identità civile non censita tra gli aventi diritto.")
            
        if self.voter_registry[student_id]:
            raise ValueError("Tentativo di doppio voto bloccato. Hai già ritirato la scheda.")

        # Segniamo che ha ritirato la scheda, così non vota due volte
        self.voter_registry[student_id] = True
        
        # Applichiamo la firma cieca con la chiave privata
        s_prime = pow(m_prime, self.d, self.n)
        return s_prime