from flask import render_template, request, jsonify, session, url_for, redirect
from app.core.client_wallet import ClientWallet
from app import app, auth_server, ateneo_pub_key, bacheca, urna, wallets, oauth

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/elettore')
def elettore():
    matricola = session.get('matricola')
    if not matricola:
        return render_template('elettore.html', step='login', matricola=None)
        
    has_voted = auth_server.voter_registry.get(matricola, False)
    wallet = wallets.get(matricola)
    
    if has_voted and wallet is None:
        step = 'already_voted'
    elif wallet is not None:
        if wallet.s_hex is None:
            step = 'unblind'
        else:
            step = 'vote'
    else:
        step = 'blind_signature'
        
    return render_template('elettore.html', step=step, matricola=matricola)

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    matricola = data.get('matricola')
    if matricola in auth_server.voter_registry:
        session['matricola'] = matricola
        return jsonify({"success": True, "message": "Autenticazione riuscita."})
    return jsonify({"success": False, "message": "Matricola non presente nell'elenco degli aventi diritto."}), 403

# Nuove route per OIDC (SSO)
@app.route('/login/sso')
def login_sso():
    redirect_uri = url_for('auth_callback', _external=True)
    return oauth.ateneo_sso.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    token = oauth.ateneo_sso.authorize_access_token()
    userinfo = token.get('userinfo')
    if userinfo:
        # L'ID Token contiene 'sub' che è la matricola nel nostro mock
        matricola = userinfo['sub']
        if matricola in auth_server.voter_registry:
            session['matricola'] = matricola
    return redirect(url_for('elettore'))

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.pop('matricola', None)
    return jsonify({"success": True})

@app.route('/api/get_blind_token', methods=['POST'])
def api_get_blind_token():
    matricola = session.get('matricola')
    if not matricola:
        return jsonify({"success": False, "message": "Elettore non autenticato."}), 401
        
    try:
        w = ClientWallet(ateneo_pub_key)
        wallets[matricola] = w
        
        m_prime = w.generate_and_blind_token()
        s_prime = auth_server.sign_blind_token(matricola, m_prime)
        
        m_hex, s_hex = w.unblind_signature(s_prime)
        
        return jsonify({
            "success": True, 
            "message": "Firma cieca ottenuta e credenziale sbloccata.",
            "m_hex": m_hex,
            "s_hex": s_hex
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400

@app.route('/api/cast_vote', methods=['POST'])
def api_cast_vote():
    matricola = session.get('matricola')
    if not matricola or matricola not in wallets:
        return jsonify({"success": False, "message": "Gettone non trovato. Richiedere il token prima di votare."}), 401
        
    data = request.json
    preference = data.get('preference')
    
    w = wallets[matricola]
    try:
        C = w.create_encrypted_ballot(preference, urna.get_public_key(), simulate_jitter=True)
        urna.cast_vote(C)
        return jsonify({"success": True, "message": "Scheda cifrata inviata all'urna con successo."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400

@app.route('/admin')
def admin():
    num_ballots = len(urna.encrypted_batch)
    return render_template('admin.html', num_ballots=num_ballots)

@app.route('/api/tally', methods=['POST'])
def api_tally():
    try:
        shares = urna.get_trustee_shares()
        presented_shares = shares[:2]
        results = urna.tally(presented_shares)
        return jsonify({"success": True, "results": results, "message": "Scrutinio completato e Bacheca aggiornata."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400

@app.route('/bacheca')
def bacheca_view():
    return render_template('bacheca.html')

@app.route('/api/bacheca', methods=['GET'])
def api_bacheca_data():
    votes = bacheca.get_all_votes()
    root = bacheca.get_merkle_root()
    root_sig = bacheca.get_root_signature()
    return jsonify({
        "success": True,
        "votes": votes,
        "merkle_root": root,
        "root_signature": root_sig
    })

@app.route('/api/verify', methods=['POST'])
def api_verify():
    data = request.json
    gettone = data.get('gettone')
    
    if not gettone:
        return jsonify({"success": False, "message": "Inserire un gettone."})
        
    if not bacheca.contains_token(gettone):
        return jsonify({"success": False, "message": "Gettone non trovato in bacheca."})
        
    proof = bacheca.get_merkle_proof(gettone)
    root = bacheca.get_merkle_root()
    is_valid = bacheca.verify_merkle_proof(gettone, proof, root)
    pref = bacheca.get_vote(gettone)
    
    return jsonify({
        "success": True,
        "is_valid": is_valid,
        "proof": proof,
        "preference": pref,
        "root": root
    })
