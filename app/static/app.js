// Helper per i messaggi di popup
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

// --- SISTEMA DI LOGGING VISUALE ---
function addLog(action, data = null) {
    const logContent = document.getElementById('log-content');
    if (!logContent) return;
    
    const time = new Date().toLocaleTimeString();
    let dataHtml = '';
    if (data) {
        if (typeof data === 'object') {
            dataHtml = `<span class="log-data">${JSON.stringify(data, null, 2)}</span>`;
        } else {
            dataHtml = `<span class="log-data">${data}</span>`;
        }
    }
    
    const entryHtml = `
        <div class="log-entry">
            <span class="log-time">[${time}]</span>
            <span class="log-action">${action}</span>
            ${dataHtml}
        </div>
    `;
    
    logContent.insertAdjacentHTML('afterbegin', entryHtml);
    
    // Auto-apri il pannello se è un evento crittografico importante e il pannello è chiuso
    const panel = document.getElementById('crypto-log-panel');
    if (panel && panel.classList.contains('hidden')) {
        panel.classList.remove('hidden');
    }
}

function toggleLog() {
    const panel = document.getElementById('crypto-log-panel');
    if (panel) {
        panel.classList.toggle('hidden');
    }
}

// --- SEZIONE ELETTORI ---
// Funzione di login
async function loginElettore() {
    const matricola = document.getElementById('matricola-input').value.trim();
    if (!matricola) {
        showAlert('Inserisci una matricola', 'error');
        return;
    }
    try {
        addLog('Rete: Richiesta di login inviata', { matricola });
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ matricola })
        });
        const data = await res.json();
        if (data.success) {
            addLog('Auth: Login riuscito. Transizione di stato nel registro.');
            setTimeout(() => location.reload(), 500); // Ricarica dopo un mezzo secondo per far vedere il log
        } else {
            showAlert(data.message, 'error');
        }
    } catch (e) {
        showAlert('Errore di connessione', 'error');
    }
}

// Uscita dell'elettore
async function logoutElettore() {
    await fetch('/api/logout', { method: 'POST' });
    location.reload();
}

// Richiesta del token accecato (Blind Signature)
async function getBlindToken() {
    addLog('Crypto: Inizio generazione gettone random e bliding factor...');
    try {
        const res = await fetch('/api/get_blind_token', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            addLog('Crypto: Blind Signature completata (firma unblinded estratta con successo)', { 
                m_hex: data.m_hex, 
                s_hex: data.s_hex 
            });
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

// Inoltro del voto cifrato all'urna
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

    addLog('Crypto: Preparazione pacchetto e cifratura Ibrida (RSA-OAEP + AES-GCM)', { preference });
    try {
        const res = await fetch('/api/cast_vote', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ preference })
        });
        const data = await res.json();
        if (data.success) {
            addLog('Rete: Pacchetto cifrato depositato nell\'urna anonimamente');
            showAlert(data.message, 'success');
            setTimeout(() => location.reload(), 2000);
        } else {
            showAlert(data.message, 'error');
        }
    } catch (e) {
        showAlert('Errore di connessione', 'error');
    }
}

// --- SEZIONE ADMIN ---
// Avvia la fase di scrutinio
async function eseguiScrutinio() {
    addLog('Admin: Avvio Scrutinio. Ricostruzione chiave RSA con Shamir Secret Sharing...');
    try {
        const res = await fetch('/api/tally', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            addLog('Admin: Scrutinio completato. Voti decifrati e conteggiati.', data.results);
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

// --- SEZIONE BACHECA ---
// Recupera tutti i voti in chiaro
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

// Verifica che un gettone specifico sia nell'albero di Merkle
async function verificaVoto() {
    const gettone = document.getElementById('verify-token-input').value.trim();
    if (!gettone) {
        showAlert('Inserisci un gettone da verificare.', 'error');
        return;
    }
    
    addLog('Bacheca: Richiesta Merkle Proof per verifica inclusione', { gettone });
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
            addLog('Crypto: Esito verifica Merkle Proof', { 
                root: data.root, 
                is_valid: data.is_valid,
                preference: data.preference
            });
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
