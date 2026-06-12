import hashlib
from Crypto.Util.number import bytes_to_long

class Urna:
    def __init__(self, ateneo_pub_key, bacheca):
        """
        Inizializza l'Urna con la chiave pubblica dell'Ateneo per la verifica 
        delle firme cieche e il riferimento alla Bacheca pubblica.
        """
        self.e, self.n = ateneo_pub_key
        self.bacheca = bacheca
        self.valid_preferences = {"SI", "NO", "SCHEDA_BIANCA"}
        
        # Registro locale dei gettoni registrati (ridondanza di sicurezza)
        self.used_tokens = set()

    def verify_signature(self, gettone_m_hex, signature_s_hex):
        """
        Verifica la validità crittografica della firma s sul gettone m.
        Formula: s^e == H(m) mod n
        """
        try:
            m_bytes = bytes.fromhex(gettone_m_hex)
            s_int = int(signature_s_hex, 16)
            
            # Calcolo H(m) mod n (RSA-FDH locale)
            h = hashlib.sha256(m_bytes).digest()
            hm_atteso = bytes_to_long(h) % self.n
            
            # Decifratura della firma
            valore_verificato = pow(s_int, self.e, self.n)
            
            return valore_verificato == hm_atteso
        except Exception:
            return False

    def cast_vote(self, gettone_m_hex, signature_s_hex, preference):
        """
        Riceve una scheda di voto anonima, la convalida e la registra.
        """
        # 1. Verifica validità preferenza
        if preference not in self.valid_preferences:
            raise ValueError(f"Preferenza '{preference}' non valida. Opzioni ammesse: {self.valid_preferences}")

        # 2. Verifica Double Voting lato Urna (TM.2)
        if gettone_m_hex in self.used_tokens or self.bacheca.contains_token(gettone_m_hex):
            raise ValueError("Tentativo di Double Voting rilevato (TM.2). Gettone già utilizzato.")

        # 3. Verifica firma cieca rilasciata dall'Ateneo
        if not self.verify_signature(gettone_m_hex, signature_s_hex):
            raise ValueError("Firma digitale del gettone non valida. Voto rifiutato.")

        # 4. Registrazione del voto nella bacheca pubblica e nel set locale
        self.used_tokens.add(gettone_m_hex)
        self.bacheca.add_vote(gettone_m_hex, preference)
        return True

    def get_tally(self):
        """
        Calcola e restituisce lo scrutinio finale dei voti presenti in Bacheca.
        """
        votes = self.bacheca.get_all_votes()
        tally = {"SI": 0, "NO": 0, "SCHEDA_BIANCA": 0}
        for pref in votes.values():
            if pref in tally:
                tally[pref] += 1
        return tally
