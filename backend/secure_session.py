# secure_server.py
import base64, os, json, sqlite3, time
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import virustotalScanner  # your existing module

app = Flask(__name__)

# --- simple SQLite logging ---
DB_PATH = 'requests_log.db'
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
      CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT,
        timestamp INTEGER,
        url TEXT,
        positives INTEGER,
        total INTEGER,
        suspicious_score REAL
      )
    ''')
    cur.execute('''
      CREATE TABLE IF NOT EXISTS clients (
        client_id TEXT PRIMARY KEY,
        public_key_pem TEXT
      )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- in-memory sessions: client_id -> {aes_key (bytes), created_at} ---
sessions = {}

# --- utility helpers ---
def store_client_public_key(client_id, public_pem):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO clients (client_id, public_key_pem) VALUES (?, ?)', (client_id, public_pem))
    conn.commit()
    conn.close()

def get_client_public_key_pem(client_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT public_key_pem FROM clients WHERE client_id = ?', (client_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def log_request(client_id, url, positives, total):
    ts = int(time.time())
    suspicious_score = (positives / total) if total else 0.0
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('INSERT INTO requests (client_id, timestamp, url, positives, total, suspicious_score) VALUES (?, ?, ?, ?, ?, ?)',
                (client_id, ts, url, positives, total, suspicious_score))
    conn.commit()
    conn.close()
    return ts, suspicious_score

# --- endpoints ---

@app.route('/register', methods=['POST'])
def register():
    """
    Client sends: { client_id, public_key_pem }
    """
    data = request.get_json()
    if not data or 'client_id' not in data or 'public_key_pem' not in data:
        return jsonify({'error': 'client_id and public_key_pem required'}), 400
    client_id = data['client_id']
    public_pem = data['public_key_pem']
    store_client_public_key(client_id, public_pem)
    return jsonify({'status': 'ok'})

@app.route('/create_session', methods=['POST'])
def create_session():
    """
    Client sends: { client_id }
    Server creates AES256 key, encrypts key with client's public key (RSA-OAEP)
    Returns: { encrypted_aes_key_b64, session_id (for server-side lookup), iv_nonce_b64_optional }
    """
    data = request.get_json()
    if not data or 'client_id' not in data:
        return jsonify({'error': 'client_id required'}), 400
    client_id = data['client_id']
    pem = get_client_public_key_pem(client_id)
    if not pem:
        return jsonify({'error': 'unknown client'}), 404

    public_key = serialization.load_pem_public_key(pem.encode('utf-8'))

    # generate AES-256-GCM key
    aes_key = os.urandom(32)  # 256-bit
    # encrypt AES key with client's RSA public key (OAEP)
    encrypted_aes = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encrypted_b64 = base64.b64encode(encrypted_aes).decode('utf-8')

    # store session (in memory for demo). You may want to persist it encrypted in DB.
    sessions[client_id] = {'aes_key': aes_key, 'created_at': int(time.time())}

    return jsonify({'encrypted_aes_key_b64': encrypted_b64})

@app.route('/analyze_secure', methods=['POST'])
def analyze_secure():
    """
    Client sends JSON:
    {
      client_id,
      ciphertext_b64,       // AES-GCM ciphertext of the plaintext payload
      iv_b64,               // AES-GCM nonce (12 bytes)
      signature_b64,        // RSA signature of plaintext
      digest_hex            // SHA-512 hex of plaintext (MDC)
    }
    Server decrypts, verifies signature & digest, forwards URL to VT, logs, encrypts response and returns:
    {
      response_ciphertext_b64,
      response_iv_b64,
      mac_b64,            // HMAC-SHA512 over ciphertext (using session key)
      mdc_hex             // SHA512 digest of plaintext response
    }
    """
    data = request.get_json()
    # basic validation
    required = ['client_id', 'ciphertext_b64', 'iv_b64', 'signature_b64', 'digest_hex']
    if not data or any(k not in data for k in required):
        return jsonify({'error': 'missing fields'}), 400
    client_id = data['client_id']
    sess = sessions.get(client_id)
    if not sess:
        return jsonify({'error': 'no active session for client. Call /create_session first'}), 400
    aes_key = sess['aes_key']

    # decode
    ciphertext = base64.b64decode(data['ciphertext_b64'])
    iv = base64.b64decode(data['iv_b64'])
    signature = base64.b64decode(data['signature_b64'])
    digest_hex = data['digest_hex']

    # decrypt AES-GCM
    try:
        aesgcm = AESGCM(aes_key)
        plaintext_bytes = aesgcm.decrypt(iv, ciphertext, None)  # no associated data used
        plaintext = plaintext_bytes.decode('utf-8')
    except Exception as e:
        return jsonify({'error': 'AES decryption failed', 'details': str(e)}), 400

    # verify digest (MDC)
    digest = crypto_hashes.Hash(crypto_hashes.SHA512())
    digest.update(plaintext_bytes)
    computed_digest_hex = digest.finalize().hex()
    if computed_digest_hex != digest_hex:
        return jsonify({'error': 'MDC mismatch'}), 400

    # verify signature using stored client public key
    public_pem = get_client_public_key_pem(client_id)
    if not public_pem:
        return jsonify({'error': 'client public key not found'}), 404
    public_key = serialization.load_pem_public_key(public_pem.encode('utf-8'))

    try:
        public_key.verify(
            signature,
            plaintext_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except Exception as e:
        return jsonify({'error': 'signature verification failed', 'details': str(e)}), 400

    # At this point the plaintext is authenticated. We expect plaintext to be a JSON with `url` field
    try:
        payload = json.loads(plaintext)
        url = payload.get('url')
        if not url:
            return jsonify({'error': 'url missing from payload'}), 400
    except Exception as e:
        return jsonify({'error': 'invalid payload json', 'details': str(e)}), 400

    # call VirusTotal (your existing function)
    vt_result = virustotalScanner.scan(url)
    # vt_result expected to be {'positives': n, 'total': m, 'scan_date': '...'} or {'error': '...'}
    if 'error' in vt_result:
        # still log and reply with error encrypted
        response_plain = json.dumps({'error': vt_result['error']})
        positives = 0
        total = 0
    else:
        positives = int(vt_result.get('positives', 0))
        total = int(vt_result.get('total', 0))
        response_plain = json.dumps({'positives': positives, 'total': total, 'scan_date': vt_result.get('scan_date', '')})

    # log this request
    ts, suspicious_score = log_request(client_id, url, positives, total)

    # prepare response encryption (AES-GCM) and MAC (HMAC-SHA512)
    response_bytes = response_plain.encode('utf-8')
    resp_iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    response_ct = aesgcm.encrypt(resp_iv, response_bytes, None)
    response_ct_b64 = base64.b64encode(response_ct).decode('utf-8')
    resp_iv_b64 = base64.b64encode(resp_iv).decode('utf-8')

    # HMAC-SHA512 over ciphertext (use session key directly for HMAC here for demo; in prod derive separate MAC key via HKDF)
    h = hmac.HMAC(aes_key, crypto_hashes.SHA512())
    h.update(response_ct)
    mac_b64 = base64.b64encode(h.finalize()).decode('utf-8')

    # MDC = SHA-512 hex of plaintext response
    md = crypto_hashes.Hash(crypto_hashes.SHA512())
    md.update(response_bytes)
    mdc_hex = md.finalize().hex()

    return jsonify({
        'response_ciphertext_b64': response_ct_b64,
        'response_iv_b64': resp_iv_b64,
        'mac_b64': mac_b64,
        'mdc_hex': mdc_hex,
        'timestamp': ts,
        'suspicious_score': suspicious_score
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
