import time
import uuid
from flask import Blueprint, request, redirect, jsonify, render_template, session
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from authlib.jose import jwt, JsonWebKey

oidc_bp = Blueprint('oidc', __name__, url_prefix='/oidc')

# Generate a keypair for the mock identity provider
oidc_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
oidc_public_key = oidc_private_key.public_key()

# In memory storage for auth codes
auth_codes = {}

# Valid matricole
valid_users = ["10002345", "10005678", "10009101"]

@oidc_bp.route('/.well-known/openid-configuration')
def openid_configuration():
    # Per Authlib, la URL dell'issuer deve combaciare con l'iss nel JWT
    return jsonify({
        "issuer": "http://127.0.0.1:5000/oidc",
        "authorization_endpoint": "http://127.0.0.1:5000/oidc/authorize",
        "token_endpoint": "http://127.0.0.1:5000/oidc/token",
        "jwks_uri": "http://127.0.0.1:5000/oidc/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    })

@oidc_bp.route('/jwks')
def jwks():
    pem = oidc_public_key.public_bytes(
        serialization.Encoding.PEM, 
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    jwk = JsonWebKey.import_key(pem, {'kty': 'RSA'})
    # Aggiungi 'alg' e 'use' per compatibilità
    jwk_dict = jwk.as_dict()
    jwk_dict['alg'] = 'RS256'
    jwk_dict['use'] = 'sig'
    jwk_dict['kid'] = 'mock-key-1'
    return jsonify({"keys": [jwk_dict]})

@oidc_bp.route('/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'GET':
        session['oidc_req'] = {
            'redirect_uri': request.args.get('redirect_uri'),
            'state': request.args.get('state'),
            'nonce': request.args.get('nonce'),
            'client_id': request.args.get('client_id')
        }
        return render_template('oidc_login.html')
    else:
        matricola = request.form.get('matricola')
        
        if matricola not in valid_users:
            return render_template('oidc_login.html', error="Matricola non valida o non censita.")
            
        req = session.get('oidc_req', {})
        if not req:
            return "Session error. Please restart login.", 400
            
        code = str(uuid.uuid4())
        auth_codes[code] = {
            'matricola': matricola,
            'nonce': req.get('nonce'),
            'redirect_uri': req.get('redirect_uri')
        }
        
        redirect_uri = req.get('redirect_uri')
        state = req.get('state')
        return redirect(f"{redirect_uri}?code={code}&state={state}")

@oidc_bp.route('/token', methods=['POST'])
def token():
    code = request.form.get('code')
    if code not in auth_codes:
        return jsonify({"error": "invalid_grant"}), 400
        
    data = auth_codes.pop(code)
    
    header = {'alg': 'RS256', 'kid': 'mock-key-1'}
    payload = {
        'iss': 'http://127.0.0.1:5000/oidc',
        'sub': data['matricola'],
        'aud': request.form.get('client_id'),
        'exp': int(time.time()) + 3600,
        'iat': int(time.time()),
        'nonce': data['nonce']
    }
    
    pem_priv = oidc_private_key.private_bytes(
        serialization.Encoding.PEM, 
        serialization.PrivateFormat.PKCS8, 
        serialization.NoEncryption()
    )
    
    id_token = jwt.encode(header, payload, pem_priv).decode('utf-8')
    
    return jsonify({
        "access_token": "mock_access_token_" + str(uuid.uuid4()),
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token
    })
