from flask import Flask
from app.core.auth_server import AuthenticationServer
from app.core.bacheca import BulletinBoard
from app.core.urna import Urna

app = Flask(__name__)
app.secret_key = 'chiave_segreta_prototipo'

# Istanze globali (in memoria) che compongono il sistema
auth_server = AuthenticationServer()
ateneo_pub_key = auth_server.get_public_key()
bacheca = BulletinBoard()
urna = Urna(ateneo_pub_key, bacheca, num_trustees=3, quorum=2)

# Conserviamo i wallet dei client in memoria simulando la persistenza locale sul dispositivo dell'elettore
wallets = {}

from app import routes
