import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import hashlib
import json
import time
from Crypto.Util.number import bytes_to_long, getPrime

from app.core.auth_server import AuthenticationServer
from app.core.client_wallet import ClientWallet
from app.core.bacheca import BulletinBoard
from app.core.urna import Urna

class TestVotingSystem(unittest.TestCase):
    def setUp(self):
        # Inizializziamo l'infrastruttura comune per i test.
        self.server = AuthenticationServer(bits=2048)
        self.pub_key = self.server.get_public_key()
        self.bacheca = BulletinBoard()
        # Num trustees = 3, Quorum = 2
        self.urna = Urna(self.pub_key, self.bacheca, num_trustees=3, quorum=2)

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
        
        # 4. Creazione scheda cifrata (AEAD) e invio all'Urna
        preference = "SI"
        C = wallet.create_encrypted_ballot(preference, self.urna.get_public_key(), simulate_jitter=False)
        self.urna.cast_vote(C)
        
        # Le schede in bacheca non compaiono finché non c'è lo scrutinio
        self.assertIsNone(self.bacheca.get_vote(m_hex))
        
        # 5. Scrutinio con quorum (2 trustees su 3)
        shares = self.urna.get_trustee_shares()[:2] 
        tally = self.urna.tally(shares)
        
        self.assertEqual(tally["SI"], 1)
        self.assertEqual(tally["NO"], 0)
        self.assertEqual(tally["SCHEDA_BIANCA"], 0)
        
        # 6. Verifica presenza in Bacheca e Merkle Tree
        recorded_pref = self.bacheca.get_vote(m_hex)
        self.assertEqual(recorded_pref, preference)

        root = self.bacheca.get_merkle_root()
        self.assertIsNotNone(root)
        proof = self.bacheca.get_merkle_proof(m_hex)
        self.assertTrue(self.bacheca.verify_merkle_proof(m_hex, proof, root))

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

    def test_double_voting_and_receipt_freeness(self):
        """
        Verifica che l'Urna applichi la deduplicazione posticipata 
        solo in fase di scrutinio per garantire la Receipt-Freeness (WP2 2.5).
        """
        student_id = "10002345"
        wallet = ClientWallet(self.pub_key)
        
        m_prime = wallet.generate_and_blind_token()
        s_prime = self.server.sign_blind_token(student_id, m_prime)
        wallet.unblind_signature(s_prime)
        
        # Voto originario "NO" (es. espresso sotto coercizione)
        C1 = wallet.create_encrypted_ballot("NO", self.urna.get_public_key(), simulate_jitter=False)
        self.urna.cast_vote(C1)
        
        time.sleep(0.01) # Garantisce che il timestamp successivo sia maggiore
        
        # Voto di sostituzione "SI" (libero e sicuro)
        C2 = wallet.create_encrypted_ballot("SI", self.urna.get_public_key(), simulate_jitter=False)
        self.urna.cast_vote(C2)
        
        # Lo scrutinio deve riflettere solo il secondo voto (SI)
        tally = self.urna.tally(self.urna.get_trustee_shares())
        self.assertEqual(tally["SI"], 1)
        self.assertEqual(tally["NO"], 0)

    def test_quorum_not_reached(self):
        """
        Verifica che l'urna non possa essere aperta se i Trustee non raggiungono il quorum (Shamir).
        """
        student_id = "10002345"
        wallet = ClientWallet(self.pub_key)
        m_prime = wallet.generate_and_blind_token()
        s_prime = self.server.sign_blind_token(student_id, m_prime)
        wallet.unblind_signature(s_prime)
        
        C = wallet.create_encrypted_ballot("SI", self.urna.get_public_key(), simulate_jitter=False)
        self.urna.cast_vote(C)
        
        # Proviamo a scrutinare con solo 1 trustee (quorum richiesto = 2)
        shares = [self.urna.get_trustee_shares()[0]]
        with self.assertRaises(ValueError):
            self.urna.tally(shares)

    def test_invalid_signature_rejection(self):
        """
        Verifica che l'Urna respinga voti con firme contraffatte o payload alterati.
        """
        student_id = "10009101"
        wallet = ClientWallet(self.pub_key)
        
        m_prime = wallet.generate_and_blind_token()
        s_prime = self.server.sign_blind_token(student_id, m_prime)
        wallet.unblind_signature(s_prime)
        
        # Contraffazione: Modifica la firma prima di creare il ballot cifrato
        wallet.s_hex = hex(int(wallet.s_hex, 16) + 1)
        
        C = wallet.create_encrypted_ballot("SI", self.urna.get_public_key(), simulate_jitter=False)
        self.urna.cast_vote(C)
        
        # Lo scrutinio lo scarta e non lo conteggia
        tally = self.urna.tally(self.urna.get_trustee_shares())
        self.assertEqual(tally["SI"], 0)

if __name__ == "__main__":
    unittest.main()

