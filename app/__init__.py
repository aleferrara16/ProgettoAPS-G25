import os
from flask import Flask
from authlib.integrations.flask_client import OAuth

from app.core.auth_server import AuthenticationServer
from app.core.bacheca import BulletinBoard
from app.core.urna import Urna
from app.core.mock_oidc_server import oidc_bp

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Istanze globali (in memoria) che compongono il sistema
auth_server = AuthenticationServer()
ateneo_pub_key = auth_server.get_public_key()
bacheca = BulletinBoard()
urna = Urna(ateneo_pub_key, bacheca, num_trustees=3, quorum=2)

# Conserviamo i wallet dei client in memoria simulando la persistenza locale sul dispositivo dell'elettore
wallets = {}

app.register_blueprint(oidc_bp)

oauth = OAuth(app)
oauth.register(
    name="ateneo_sso",
    client_id="mock-client-id",
    client_secret="mock-client-secret",
    server_metadata_url="http://127.0.0.1:5000/oidc/.well-known/openid-configuration",
    client_kwargs={"scope": "openid"}
)

from app import routes
