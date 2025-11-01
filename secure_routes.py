# secure_routes.py
from flask import Blueprint, request, jsonify
import json
import secure_session
import virustotalScanner

secure_bp = Blueprint('secure_bp', __name__)

# Ensure database is ready
secure_session.init_db()


@secure_bp.route('/register', methods=['POST'])
def register_client():
    """Client sends its RSA public key for registration."""
    data = request.get_json()
    if not data or 'client_id' not in data or 'public_key_pem' not in data:
        return jsonify({'error': 'client_id and public_key_pem required'}), 400

    secure_session.store_client_public_key(data['client_id'], data['public_key_pem'])
    return jsonify({'status': 'registered'})


@secure_bp.route('/create_session', methods=['POST'])
def create_session():
    """Generate AES key for client and encrypt it with their public RSA key."""
    data = request.get_json()
    if not data or 'client_id' not in data:
        return jsonify({'error': 'client_id required'}), 400

    client_id = data['client_id']
    public_pem = secure_session.get_client_public_key_pem(client_id)
    if not public_pem:
        return jsonify({'error': 'unknown client'}), 404

    encrypted_aes_b64 = secure_session.create_session_for_client(client_id, public_pem)
    return jsonify({'encrypted_aes_key_b64': encrypted_aes_b64})


@secure_bp.route('/analyze_secure', methods=['POST'])
def analyze_secure():
    """Handle encrypted requests and respond securely."""
    data = request.get_json()
    required = ['client_id', 'ciphertext_b64', 'iv_b64', 'signature_b64', 'digest_hex']
    if not data or any(k not in data for k in required):
        return jsonify({'error': 'missing fields'}), 400

    client_id = data['client_id']

    # Decrypt and verify
    plaintext, error = secure_session.decrypt_and_verify_request(
        client_id,
        data['ciphertext_b64'],
        data['iv_b64'],
        data['signature_b64'],
        data['digest_hex']
    )
    if error:
        return jsonify(error), 400

    try:
        payload = json.loads(plaintext)
        url = payload.get('url')
    except Exception as e:
        return jsonify({'error': 'invalid JSON payload', 'details': str(e)}), 400

    if not url:
        return jsonify({'error': 'url missing'}), 400

    # Call VirusTotal
    vt_result = virustotalScanner.scan(url)
    if 'error' in vt_result:
        result = {'error': vt_result['error']}
        positives, total = 0, 0
    else:
        positives = int(vt_result.get('positives', 0))
        total = int(vt_result.get('total', 0))
        result = {
            'positives': positives,
            'total': total,
            'scan_date': vt_result.get('scan_date', '')
        }

    # Log
    ts, suspicious_score = secure_session.log_request(client_id, url, positives, total)
    result.update({'timestamp': ts, 'suspicious_score': suspicious_score})

    # Encrypt response
    aes_key = secure_session.sessions[client_id]['aes_key']
    enc_response = secure_session.encrypt_response(aes_key, result)

    return jsonify(enc_response)
