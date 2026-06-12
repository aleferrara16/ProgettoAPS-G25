class BulletinBoard:
    def __init__(self):
        # Elenco dei voti registrati. Struttura: { gettone_m (hex): preferenza (str) }
        self._votes = {}

    def add_vote(self, gettone_m, preference):
        """
        Aggiunge un voto anonimo nella bacheca pubblica.
        """
        if gettone_m in self._votes:
            raise ValueError("Gettone già presente in bacheca.")
        self._votes[gettone_m] = preference

    def get_vote(self, gettone_m):
        """
        Consente a un elettore di verificare se il proprio gettone è presente e
        quale preferenza è stata registrata (Receipt-Freeness / Verificabilità).
        """
        return self._votes.get(gettone_m, None)

    def get_all_votes(self):
        """
        Ritorna una copia di tutti i voti registrati (anonimi).
        """
        return dict(self._votes)

    def contains_token(self, gettone_m):
        """
        Controlla se un gettone è già presente.
        """
        return gettone_m in self._votes
