// Utility per mostrare i messaggi
function showAlert(message, type) {
    const box = document.getElementById('alert-box');
    if (!box) return;
    box.textContent = message;
    box.className = `alert ${type}`;
    box.style.display = 'block';
    setTimeout(() => {
        box.style.display = 'none';
    }, 5000);
}

// ELEPPORE: Login
async function loginElettore() {
    const matricola = document.getElementById('matricola-input').value.trim();
    if (!matricola) {
        showAlert('Inserisci una matricola', 'error');
        return;
    }
    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ matricola })
        });
        const data = await res.json();
        if (data.success) {
            location.reload(); // Ricarica la pagina per andare allo step successivo
        } else {
            showAlert(data.message, 'error');
        }
    } catch (e) {
        showAlert('Errore di connessione', 'error');
    }
}

// ELEPPORE: Logout
async function logoutElettore() {
    await fetch('/api/logout', { method: 'POST' });
    location.reload();
}

// ELEPPORE: Richiedi token
async function getBlindToken() {
    try {
        const res = await fetch('/api/get_blind_token', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            document.getElementById('token-m').textContent = data.m_hex;
            document.getElementById('token-s').textContent = data.s_hex;
            document.getElementById('token-result').classList.remove('hidden');
            showAlert(data.message, 'success');
        } else {
            showAlert(data.message, 'error');
        }
    } catch (e) {
        showAlert('Errore di connessione', 'error');
    }
}

// ELEPPORE: Cifra e Invia Voto
async function castVote() {
    const radios = document.getElementsByName('preference');
    let preference = null;
    for (let r of radios) {
        if (r.checked) preference = r.value;
    }
    if (!preference) {
        showAlert('Seleziona una preferenza.', 'error');
        return;
    }

    try {
        const res = await fetch('/api/cast_vote', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ preference })
        });
        const data = await res.json();
        if (data.success) {
            showAlert(data.message, 'success');
            setTimeout(() => location.reload(), 2000);
        } else {
            showAlert(data.message, 'error');
        }
    } catch (e) {
        showAlert('Errore di connessione', 'error');
    }
}

// ADMIN: Scrutinio
async function eseguiScrutinio() {
    try {
        const res = await fetch('/api/tally', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            showAlert(data.message, 'success');
            const ul = document.getElementById('tally-list');
            ul.innerHTML = '';
            for (const [pref, count] of Object.entries(data.results)) {
                const li = document.createElement('li');
                li.textContent = `${pref}: ${count} voti`;
                ul.appendChild(li);
            }
            document.getElementById('scrutinio-result').classList.remove('hidden');
        } else {
            showAlert(data.message, 'error');
        }
    } catch (e) {
        showAlert('Errore di connessione', 'error');
    }
}

// BACHECA: Carica dati
async function fetchBachecaData() {
    const tbody = document.getElementById('votes-tbody');
    const rootSpan = document.getElementById('merkle-root');
    const rootSigSpan = document.getElementById('root-signature');
    if (!tbody) return;

    try {
        const res = await fetch('/api/bacheca');
        const data = await res.json();
        if (data.success) {
            rootSpan.textContent = data.merkle_root || "Non ancora calcolata";
            if (rootSigSpan) {
                rootSigSpan.textContent = data.root_signature || "Non ancora calcolata";
            }
            tbody.innerHTML = '';
            for (const [m_hex, pref] of Object.entries(data.votes)) {
                const tr = document.createElement('tr');
                const td1 = document.createElement('td');
                td1.className = 'mono-text';
                td1.textContent = m_hex;
                const td2 = document.createElement('td');
                td2.textContent = pref;
                tr.appendChild(td1);
                tr.appendChild(td2);
                tbody.appendChild(tr);
            }
        }
    } catch (e) {
        console.error(e);
    }
}

// BACHECA: Verifica voto (Merkle)
async function verificaVoto() {
    const gettone = document.getElementById('verify-token-input').value.trim();
    if (!gettone) {
        showAlert('Inserisci un gettone da verificare.', 'error');
        return;
    }
    try {
        const res = await fetch('/api/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ gettone })
        });
        const data = await res.json();
        const resBox = document.getElementById('verify-result');
        resBox.classList.remove('hidden');
        
        if (data.success) {
            resBox.innerHTML = `
                <p><strong>Preferenza Registrata:</strong> ${data.preference}</p>
                <p><strong>Stato Merkle Proof:</strong> ${data.is_valid ? '<span style="color:green">VALIDA</span>' : '<span style="color:red">INVALIDA</span>'}</p>
                <p style="font-size:0.8rem">Root attesa: ${data.root}</p>
            `;
        } else {
            resBox.innerHTML = `<p style="color:red">${data.message}</p>`;
        }
    } catch (e) {
        showAlert('Errore di connessione', 'error');
    }
}
