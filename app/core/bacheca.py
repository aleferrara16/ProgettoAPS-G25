from cryptography.hazmat.primitives import hashes

class BulletinBoard:
    def __init__(self):
        # Elenco dei voti registrati. Struttura: { gettone_m (hex): preferenza (str) }
        self._votes = {}
        # Strutture per l'Albero di Merkle
        self._tree = []
        self._merkle_root = None
        self._root_signature = None

    def add_vote(self, gettone_m, preference):
        """
        Aggiunge un voto anonimo nella bacheca pubblica.
        Gestisce la Receipt-Freeness aggiornando la preferenza se il gettone esiste già.
        """
        self._votes[gettone_m] = preference

    def _hash(self, data_bytes):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data_bytes)
        return digest.finalize().hex()

    def build_merkle_tree(self):
        """
        Costruisce il Merkle Tree dei gettoni ammessi per la verifica universale e individuale.
        Corrisponde alla fase 2.7 del WP2.
        """
        tokens = sorted(list(self._votes.keys()))
        if not tokens:
            self._merkle_root = None
            self._tree = []
            return None

        # Level 0 (leaves)
        leaves = [self._hash(t.encode()) for t in tokens]
        
        tree = [leaves]
        current_level = leaves
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i+1]
                else:
                    right = left # Duplica l'ultimo nodo se dispari
                
                combined = self._hash((left + right).encode())
                next_level.append(combined)
                
            tree.append(next_level)
            current_level = next_level
            
        self._tree = tree
        self._merkle_root = tree[-1][0]
        return self._merkle_root

    def get_merkle_root(self):
        return self._merkle_root
        
    def set_root_signature(self, signature_hex):
        self._root_signature = signature_hex
        
    def get_root_signature(self):
        return self._root_signature

    def get_merkle_proof(self, gettone_m):
        """
        Fornisce la prova di inclusione (Merkle Proof) per un gettone.
        Restituisce una lista di tuple (hash_fratello, bool_se_fratello_a_sinistra)
        """
        if gettone_m not in self._votes or not self._tree:
            return None
            
        tokens = sorted(list(self._votes.keys()))
        try:
            index = tokens.index(gettone_m)
        except ValueError:
            return None
            
        proof = []
        for level in self._tree[:-1]:
            is_right_node = index % 2 != 0
            sibling_index = index - 1 if is_right_node else index + 1
            
            if sibling_index < len(level):
                sibling_hash = level[sibling_index]
            else:
                sibling_hash = level[index] # Caso dispari duplicato
                
            proof.append((sibling_hash, is_right_node))
            index //= 2
            
        return proof

    def verify_merkle_proof(self, gettone_m, proof, root):
        """
        Verifica lato client se la proof corrisponde alla root.
        """
        current_hash = self._hash(gettone_m.encode())
        for sibling_hash, is_right_node in proof:
            if is_right_node:
                combined = sibling_hash + current_hash
            else:
                combined = current_hash + sibling_hash
            current_hash = self._hash(combined.encode())
            
        return current_hash == root

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
