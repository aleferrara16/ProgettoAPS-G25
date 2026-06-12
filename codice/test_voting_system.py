import unittest
import hashlib
from Crypto.Util.number import bytes_to_long, getPrime

from auth_server import AuthenticationServer
from client_wallet import ClientWallet
from bacheca import BulletinBoard
from urna import Urna

class TestVotingSystem(unittest.TestCase):
    def setUp(self):
        # Inizializziamo l'infrastruttura comune per i test.
        # Usiamo chiavi a 1024 bit per velocizzare l'esecuzione dei test unitari.
        self.server = AuthenticationServer(bits=1024)
        self.pub_key = self.server.get_public_key()
        self.bacheca = BulletinBoard()
        self.urna = Urna(self.pub_key, self.bacheca)

    def test_successful_vote_flow(self):
        """
        Testa il flusso di voto completo e corretto di un utente avente diritto.
        """
        student_id = "10002345"
        wallet = ClientWallet(self.pub_key)
        
        # 1. Generazione e blinding
        m_prime = wallet.generate_and_blind_token()
        
        # 2. Firma cieca sul server di autenticazione
        s_prime = self.server.sign_blind_token(student_id, m_prime)
        
        # 3. Unblinding lato client per ottenere (m, s)
        m_hex, s_hex = wallet.unblind_signature(s_prime)
        
        # 4. Invio del voto all'Urna
        preference = "SI"
        success = self.urna.cast_vote(m_hex, s_hex, preference)
        
        self.assertTrue(success)
        
        # 5. Verifica presenza in Bacheca
        recorded_pref = self.bacheca.get_vote(m_hex)
        self.assertEqual(recorded_pref, preference)
        
        # 6. Verifica scrutinio
        tally = self.urna.get_tally()
        self.assertEqual(tally["SI"], 1)
        self.assertEqual(tally["NO"], 0)
        self.assertEqual(tally["SCHEDA_BIANCA"], 0)

    def test_double_voting_at_auth_server(self):
        """
        Verifica che un elettore non possa ritirare più di un gettone firmato (TM.1).
        """
        student_id = "10005678"
        wallet1 = ClientWallet(self.pub_key)
        wallet2 = ClientWallet(self.pub_key)
        
        m_prime1 = wallet1.generate_and_blind_token()
        m_prime2 = wallet2.generate_and_blind_token()
        
        # Primo ritiro: successo
        self.server.sign_blind_token(student_id, m_prime1)
        
        # Secondo ritiro con lo stesso ID: fallimento
        with self.assertRaises(ValueError) as context:
            self.server.sign_blind_token(student_id, m_prime2)
        
        self.assertIn("Double Voting", str(context.exception))

    def test_double_voting_at_urna(self):
        """
        Verifica che lo stesso gettone non possa essere speso due volte nell'Urna (TM.2).
        """
        student_id = "10002345"
        wallet = ClientWallet(self.pub_key)
        
        m_prime = wallet.generate_and_blind_token()
        s_prime = self.server.sign_blind_token(student_id, m_prime)
        m_hex, s_hex = wallet.unblind_signature(s_prime)
        
        # Primo voto: successo
        self.urna.cast_vote(m_hex, s_hex, "SI")
        
        # Secondo voto con lo stesso gettone: fallimento
        with self.assertRaises(ValueError) as context:
            self.urna.cast_vote(m_hex, s_hex, "NO")
            
        self.assertIn("Double Voting", str(context.exception))
        
        # Lo scrutinio deve riflettere solo il primo voto
        tally = self.urna.get_tally()
        self.assertEqual(tally["SI"], 1)
        self.assertEqual(tally["NO"], 0)

    def test_unregistered_student(self):
        """
        Verifica che un utente non registrato o non avente diritto venga respinto dall'Auth Server.
        """
        student_id = "99999999" # Non presente nel database dell'ateneo
        wallet = ClientWallet(self.pub_key)
        m_prime = wallet.generate_and_blind_token()
        
        with self.assertRaises(ValueError) as context:
            self.server.sign_blind_token(student_id, m_prime)
            
        self.assertIn("Identità civile non censita", str(context.exception))

    def test_invalid_signature_rejection(self):
        """
        Verifica che l'Urna respinga voti con firme contraffatte o gettoni modificati.
        """
        student_id = "10009101"
        wallet = ClientWallet(self.pub_key)
        
        m_prime = wallet.generate_and_blind_token()
        s_prime = self.server.sign_blind_token(student_id, m_prime)
        m_hex, s_hex = wallet.unblind_signature(s_prime)
        
        # Caso 1: Firma modificata (contraffazione)
        s_int = int(s_hex, 16)
        forged_s_hex = hex((s_int + 1) % self.pub_key[1])
        
        with self.assertRaises(ValueError) as context:
            self.urna.cast_vote(m_hex, forged_s_hex, "SI")
        self.assertIn("Firma digitale del gettone non valida", str(context.exception))
        
        # Caso 2: Gettone modificato mantenendo la stessa firma
        m_bytes = bytes.fromhex(m_hex)
        modified_m_bytes = bytearray(m_bytes)
        modified_m_bytes[0] ^= 0xFF # Modifica un byte del gettone
        modified_m_hex = modified_m_bytes.hex()
        
        with self.assertRaises(ValueError) as context:
            self.urna.cast_vote(modified_m_hex, s_hex, "SI")
        self.assertIn("Firma digitale del gettone non valida", str(context.exception))

    def test_invalid_preference_rejection(self):
        """
        Verifica che preferenze non valide vengano rifiutate dall'Urna.
        """
        student_id = "10002345"
        wallet = ClientWallet(self.pub_key)
        
        m_prime = wallet.generate_and_blind_token()
        s_prime = self.server.sign_blind_token(student_id, m_prime)
        m_hex, s_hex = wallet.unblind_signature(s_prime)
        
        with self.assertRaises(ValueError) as context:
            self.urna.cast_vote(m_hex, s_hex, "ASTENUTO") # Non presente tra SI, NO, SCHEDA_BIANCA
        self.assertIn("Preferenza 'ASTENUTO' non valida", str(context.exception))

    def test_cryptographic_decoupling_anonymity(self):
        """
        Verifica concettuale dell'anonimato matematico del protocollo.
        Mostra che il server di autenticazione, pur conoscendo m' e s',
        non può correlare questi valori a m e s usati per votare
        senza conoscere il fattore di accecamento segreto r del client.
        """
        student_id = "10002345"
        wallet = ClientWallet(self.pub_key)
        
        m_prime = wallet.generate_and_blind_token()
        s_prime = self.server.sign_blind_token(student_id, m_prime)
        m_hex, s_hex = wallet.unblind_signature(s_prime)
        
        m_int = bytes_to_long(bytes.fromhex(m_hex))
        s_int = int(s_hex, 16)
        
        # Senza la conoscenza di wallet.r, il server di autenticazione vede solo m_prime e s_prime
        # Verifichiamo che la relazione algebrica contenga il fattore r:
        # m' = H(m) * r^e mod n
        # s' = s * r mod n
        hm = wallet._full_domain_hash(wallet.m)
        r_pow_e = pow(wallet.r, self.pub_key[0], self.pub_key[1])
        
        self.assertEqual(m_prime, (hm * r_pow_e) % self.pub_key[1])
        self.assertEqual(s_prime, (s_int * wallet.r) % self.pub_key[1])
        
        # Se provassimo a mettere in relazione diretta m' e m senza r, il controllo fallirebbe
        self.assertNotEqual(m_prime, hm)
        self.assertNotEqual(s_prime, s_int)

if __name__ == "__main__":
    unittest.main()
