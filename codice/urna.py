import hashlib
import json
from Crypto.Util.number import bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.SecretSharing import Shamir

class Urna:
    def __init__(self, ateneo_pub_key, bacheca, num_trustees=3, quorum=2):
        """
        Inizializza l'Urna con la chiave pubblica dell'Ateneo per la verifica 
        delle firme cieche e il riferimento alla Bacheca pubblica.
        Implementa la generazione della chiave di Urna e Shamir Secret Sharing.
        """
        self.e, self.n = ateneo_pub_key
        self.bacheca = bacheca
        self.valid_preferences = {"SI", "NO", "SCHEDA_BIANCA"}
        
        # 1. Setup Chiave dell'Urna e Shamir Secret Sharing
        urna_key = RSA.generate(2048)
        self.PK_urna = urna_key.publickey()
        
        import secrets
        self.master_key = secrets.token_bytes(16)
        self.trustee_shares = Shamir.split(quorum, num_trustees, self.master_key)
        
        # Cifriamo la chiave privata RSA dell'Urna con la master_key
        sk_bytes = urna_key.export_key()
        cipher = AES.new(self.master_key, AES.MODE_GCM)
        self.sk_ciphertext, self.sk_tag = cipher.encrypt_and_digest(sk_bytes)
        self.sk_nonce = cipher.nonce
        
        # L'urna dimentica il segreto (simulazione)
        urna_key = None
        self.master_key = None
        
        # Batch dei pacchetti cifrati
        self.encrypted_batch = []

    def get_public_key(self):
        return self.PK_urna

    def get_trustee_shares(self):
        return self.trustee_shares

    def verify_signature(self, gettone_m_hex, signature_s_hex):
        """
        Verifica la validità crittografica della firma s sul gettone m.
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

    def cast_vote(self, C):
        """
        Riceve il pacchetto cifrato C = (iv || Ckey || Csym || tau) e lo mette in coda.
        Nessuna decifratura viene eseguita qui, garantendo l'anonimato fino allo scrutinio.
        """
        self.encrypted_batch.append(C)
        return True

    def tally(self, presented_shares):
        """
        Esegue lo scrutinio: ricostruisce la chiave, decifra, deduplica e somma.
        """
        # 1. Ricostruzione del segreto
        try:
            master_key = Shamir.combine(presented_shares)
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=self.sk_nonce)
            sk_bytes = cipher.decrypt_and_verify(self.sk_ciphertext, self.sk_tag)
            sk_urna = RSA.import_key(sk_bytes)
        except Exception as e:
            raise ValueError("Ricostruzione della chiave fallita. Quorum non raggiunto o quote invalide.")

        cipher_rsa = PKCS1_OAEP.new(sk_urna)
        
        valid_votes = {} # { gettone_m : (timestamp, preferenza) }
        
        # 2. Decifratura e Validazione
        for C in self.encrypted_batch:
            try:
                # Estrazione componenti: iv (12 bytes), Ckey (256 bytes per RSA 2048), tau (16 bytes), Csym (resto)
                iv = C[:12]
                ckey = C[12:12+256]
                tau = C[-16:]
                csym = C[12+256:-16]
                
                # Decapsulamento chiave simmetrica
                ksym = cipher_rsa.decrypt(ckey)
                
                # Decifratura payload (AEAD)
                cipher_aes = AES.new(ksym, AES.MODE_GCM, nonce=iv)
                cipher_aes.update(ckey) # AAD = Ckey
                payload = cipher_aes.decrypt_and_verify(csym, tau)
                
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
                # Scarta pacchetti malformati o alterati (verifica tau o RSA fallita)
                continue

        # 3. Aggregazione e popolamento Bacheca
        tally_results = {p: 0 for p in self.valid_preferences}
        for m_hex, (ts, pref) in valid_votes.items():
            self.bacheca.add_vote(m_hex, pref)
            tally_results[pref] += 1
            
        # Costruisce il Merkle tree
        self.bacheca.build_merkle_tree()
            
        return tally_results
