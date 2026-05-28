"""
Flask Backend API for Malicious URL Detection System
Serves the web interface and provides REST API for URL classification.
"""

from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS
import joblib
import json
import os
import re
import time
from datetime import datetime
from features import extract_features, get_feature_names

app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)

# ─── General Structural Risk Engine ─────────────────────────────────────────
# Scores a URL 0-10 purely on its STRUCTURE, independent of specific keywords.
# A legitimate URL should score near 0. A phishing URL scores 5+.

# Action verbs that appear in domain names of phishing sites
_ACTION_WORDS = {
    'login', 'verify', 'secure', 'update', 'account', 'signin',
    'banking', 'password', 'billing', 'confirm', 'wallet', 'recover',
    'unlock', 'validate', 'authenticate', 'support', 'alert', 'suspended',
    'verify', 'activation', 'reset', 'notification', 'service',
}

# Words that appear in malware/dropper domain names  
_DROPPER_WORDS = {
    'crack', 'keygen', 'warez', 'nulled', 'torrent', 'hack', 'exploit',
    'payload', 'backdoor', 'rootkit', 'crypter', 'loader', 'stealer',
    'cheat', 'free', 'download', 'install', 'setup',
}

# Executables that should never appear in a safe URL
_EXEC_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.vbs', '.ps1', '.msi', '.scr',
    '.pif', '.jar', '.apk', '.sh', '.dll', '.lnk',
}


def _structural_risk_score(url: str, ext) -> tuple[int, list[str]]:
    """
    Computes a GENERAL structural risk score (0-15).
    Works on the SHAPE of the URL, not hardcoded lists.
    Any phishing-shaped URL will score high regardless of which brand it fakes.
    """
    sld   = ext.domain.lower()
    tld   = ext.suffix.lower()
    u     = url.lower()
    path  = u.split('?')[0]
    score = 0
    reasons = []

    # 1. Hyphen count in SLD (legit domains rarely have > 1 hyphen)
    hyphens = sld.count('-')
    if hyphens >= 4:
        score += 4
        reasons.append(f"{hyphens} hyphens in domain name")
    elif hyphens >= 2:
        score += 2
        reasons.append(f"{hyphens} hyphens in domain name")

    # 2. Word count in SLD when split by hyphens (phishing domains look like sentences)
    words = [w for w in sld.split('-') if w]
    if len(words) >= 5:
        score += 3
        reasons.append(f"{len(words)} words in domain name")
    elif len(words) >= 3:
        score += 1

    # 3. SLD length (very long domain names are suspicious)
    if len(sld) > 30:
        score += 3
        reasons.append(f"domain name is {len(sld)} characters long")
    elif len(sld) > 20:
        score += 1

    # 4. Action verbs IN the domain name itself (the strongest general signal)
    action_in_sld = [w for w in _ACTION_WORDS if w in sld]
    if len(action_in_sld) >= 2:
        score += 4
        reasons.append(f"action words in domain: {', '.join(action_in_sld[:3])}")
    elif len(action_in_sld) == 1:
        score += 2
        reasons.append(f"action word in domain: {action_in_sld[0]}")

    # 5. Dropper/malware words in domain or path
    dropper_in_url = [w for w in _DROPPER_WORDS if w in sld or w in path]
    if dropper_in_url:
        score += 3
        reasons.append(f"malware words: {', '.join(dropper_in_url[:3])}")

    # 6. Executable extension in path
    if any(path.endswith(e) or (e + '?') in path for e in _EXEC_EXTENSIONS):
        score += 5
        reasons.append("executable file in URL path")

    # 7. Raw IP address (never in a legitimate branded URL)
    if ext.domain.replace('.', '').isdigit():
        score += 3
        reasons.append("raw IP address instead of domain")

    return score, reasons


def _rule_override(url: str, ml_prediction: str, ml_confidence: float, feature_dict: dict):
    """
    General post-ML override using structural risk scoring.
    Does NOT rely on hardcoded brand lists or specific keyword matches.
    """
    import tldextract
    ext = tldextract.extract(url)

    struct_score, struct_reasons = _structural_risk_score(url, ext)

    # ── HYBRID RULE: Malware Extension Override ──────────────────────────────
    if feature_dict.get('has_malware_extension', 0) == 1:
        # Boost malware probability heavily
        return 'malware', max(ml_confidence, 0.95), True, [{
            'icon': '💀',
            'label': 'Definitive Malware Extension Detected',
            'detail': 'URL directly serves a known malware or script executable format.'
        }]

    # ── Malware dropper words → always MALWARE ────────────────────────────────
    if any(r for r in struct_reasons if 'malware words' in r):
        if ml_prediction == 'benign':
            return 'malware', 0.93, True, [{
                'icon': '🦠',
                'label': 'Malware Distribution Pattern',
                'detail': f'URL structure matches known malware dropper patterns. ({"; ".join(struct_reasons[:2])})'
            }]

    # ── High structural risk → PHISHING (general catch-all) ──────────────────
    # Score ≥ 5 means the URL SHAPE is suspicious, regardless of specific words
    if struct_score >= 5 and ml_prediction == 'benign':
        confidence = min(0.60 + struct_score * 0.03, 0.97)
        return 'phishing', confidence, True, [{
            'icon': '🔍',
            'label': 'Suspicious URL Structure Detected',
            'detail': f'Structural risk score: {struct_score}/15. Indicators: {"; ".join(struct_reasons[:3])}'
        }]

    # ── Medium risk with low ML confidence → PHISHING (borderline) ───────────
    if struct_score >= 3 and ml_prediction == 'benign' and ml_confidence < 0.70:
        return 'phishing', 0.72, True, [{
            'icon': '⚠️',
            'label': 'Moderate Structural Risk',
            'detail': f'ML confidence was low ({ml_confidence*100:.0f}%) with structural score {struct_score}/15. ({"; ".join(struct_reasons[:2])})'
        }]

    return ml_prediction, ml_confidence, False, []


# ─── Paths (all relative to this file's directory) ───────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR   = os.path.join(BASE_DIR, '..', 'model')
BUNDLE_PATH  = os.path.join(MODEL_DIR, 'model_bundle.pkl')
STATS_PATH   = os.path.join(MODEL_DIR, 'model_stats.json')
HISTORY_PATH = os.path.join(BASE_DIR, 'history.json')

model = None
encoder = None
model_stats = {}


def load_model():
    """Load the trained model and encoder from disk."""
    global model, encoder, model_stats
    try:
        if os.path.exists(BUNDLE_PATH):
            print("Loading trained model bundle...")
            bundle = joblib.load(BUNDLE_PATH)
            model = bundle['model']
            encoder = bundle['encoder']
            print("Model and encoder loaded successfully.")
        else:
            print("Model files not found. Please run train_model.py first.")

        if os.path.exists(STATS_PATH):
            with open(STATS_PATH, 'r') as f:
                model_stats = json.load(f)
            print("Model stats loaded.")
    except Exception as e:
        print(f"Error loading model: {e}")


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Serve the main web interface."""
    return render_template('index.html')


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'encoder_loaded': encoder is not None,
    })


@app.route('/stats', methods=['GET'])
def stats():
    """Return model performance statistics."""
    if not model_stats:
        return jsonify({'error': 'Model stats not available'}), 404
    return jsonify(model_stats)


@app.route('/history', methods=['GET'])
def get_history():
    """Return analysis history."""
    try:
        if os.path.exists(HISTORY_PATH):
            with open(HISTORY_PATH, 'r') as f:
                history = json.load(f)
            return jsonify(history)
        return jsonify([])
    except Exception as e:
        return jsonify([])


@app.route('/history', methods=['DELETE'])
def clear_history():
    """Clear analysis history."""
    try:
        with open(HISTORY_PATH, 'w') as f:
            json.dump([], f)
        return jsonify({"status": "cleared"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/analytics')
def analytics_page():
    """Render the dedicated analytics dashboard."""
    return render_template('stats.html')

@app.route('/predict', methods=['POST'])
def predict():
    """
    Classify a URL as malicious or benign.
    
    Request body: { "url": "https://example.com" }
    Response: {
        "url": "...",
        "prediction": "benign" | "phishing" | "malware" | "defacement",
        "is_malicious": bool,
        "confidence": float (0-1),
        "class_probabilities": {...},
        "feature_values": {...},
        "feature_importances": [...],
        "top_flags": [...],
        "processing_time_ms": float
    }
    """
    start_time = time.time()

    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing "url" field in request body'}), 400

    url = str(data['url']).strip()
    if not url:
        return jsonify({'error': 'URL cannot be empty'}), 400

    if len(url) > 2048:
        return jsonify({'error': 'URL too long (max 2048 characters)'}), 400

    if model is None or encoder is None:
        return jsonify({'error': 'Model not loaded. Please run train_model.py first.'}), 503

    try:
        # Extract features
        feature_vector, feature_dict = extract_features(url)

        # Model prediction
        import numpy as np
        X = np.array([feature_vector])
        pred_encoded = model.predict(X)[0]
        pred_proba = model.predict_proba(X)[0]

        prediction = encoder.inverse_transform([pred_encoded])[0]
        confidence = float(max(pred_proba))

        # ── Whitelist Bypass ──────────────────────────────────────────────
        # If the URL is on a known official domain, always return benign.
        from features import OFFICIAL_WHITELIST
        import tldextract
        ext = tldextract.extract(url)
        root_domain = f"{ext.domain}.{ext.suffix}".lower()

        if root_domain in OFFICIAL_WHITELIST:
            prediction = 'benign'
            confidence = 1.0
            top_flags = [{
                'icon': '✅',
                'label': 'Verified Official Domain',
                'detail': f'{root_domain} is a trusted and verified domain.'
            }]
        else:
            # ── Apply rule-based override engine ──────────────────────────────
            prediction, confidence, was_overridden, rule_flags = _rule_override(
                url, prediction, confidence, feature_dict
            )
            # Merge: rule flags first (most critical), then ML flags
            ml_flags = _generate_flags(url, feature_dict, prediction)
            top_flags = rule_flags + [f for f in ml_flags if f not in rule_flags]

        # Class probabilities
        class_probs = {
            cls: round(float(prob), 4)
            for cls, prob in zip(encoder.classes_, pred_proba)
        }

        # Feature importances (from model)
        importances = model.feature_importances_
        feature_names = get_feature_names()
        feature_importance_list = [
            {
                'feature': name,
                'importance': round(float(imp), 6),
                'value': round(float(feature_dict.get(name, 0)), 4),
                'display_name': name.replace('_', ' ').title(),
            }
            for name, imp in zip(feature_names, importances)
        ]
        feature_importance_list.sort(key=lambda x: x['importance'], reverse=True)
        is_malicious = prediction != 'benign'
        processing_time = round((time.time() - start_time) * 1000, 2)

        result = {
            'url': url,
            'prediction': prediction,
            'is_malicious': is_malicious,
            'confidence': round(confidence, 4),
            'class_probabilities': class_probs,
            'feature_values': {k: round(float(v), 4) for k, v in feature_dict.items()},
            'feature_importances': feature_importance_list[:15],  # top 15
            'top_flags': top_flags,
            'processing_time_ms': processing_time,
            'timestamp': datetime.now().isoformat()
        }

        # Save to history
        try:
            history = []
            if os.path.exists(HISTORY_PATH):
                with open(HISTORY_PATH, 'r') as f:
                    history = json.load(f)
            # Insert at beginning
            history.insert(0, {
                'url': url,
                'prediction': prediction,
                'confidence': round(confidence, 4),
                'timestamp': result['timestamp']
            })
            # Keep only last 50
            history = history[:50]
            with open(HISTORY_PATH, 'w') as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            print(f"Error saving history: {e}")

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500


def _generate_flags(url, features, prediction):
    """Generate human-readable flags explaining why a URL may be malicious."""
    flags = []
    url_lower = url.lower()

    if features.get('url_length', 0) > 75:
        flags.append({
            'icon': '📏',
            'label': 'Abnormal URL Length',
            'detail': f"URL is {int(features['url_length'])} characters (suspicious if >75)"
        })

    if features.get('has_ip_address', 0):
        flags.append({
            'icon': '🌐',
            'label': 'IP Address Used Instead of Domain',
            'detail': 'Using raw IP addresses is a common phishing tactic'
        })

    if features.get('has_payload_keyword', 0):
        flags.append({
            'icon': '📦',
            'label': 'Malware Payload Keywords',
            'detail': 'URL contains terms common in malware distribution (e.g., download, patch, crack)'
        })

    if features.get('has_command_pattern', 0):
        flags.append({
            'icon': '💻',
            'label': 'Command Injection Pattern',
            'detail': 'URL contains shell commands or execution patterns (e.g., cmd=, exec=)'
        })

    if features.get('has_auth_path', 0):
        flags.append({
            'icon': '🔑',
            'label': 'Authentication Phishing Path',
            'detail': 'URL tries to mimic a login or account verification page'
        })

    if features.get('has_defacement_signature', 0):
        flags.append({
            'icon': '🏴‍☠️',
            'label': 'Hacker Signature Detected',
            'detail': 'URL contains common hacker group signatures (e.g., hacked, owned, pwned)'
        })

    if features.get('has_sqli_pattern', 0):
        flags.append({
            'icon': '💉',
            'label': 'SQL Injection Detected',
            'detail': 'URL contains database manipulation payloads (e.g., union select, or 1=1)'
        })

    if features.get('num_subdomains', 0) > 3:
        flags.append({
            'icon': '🔗',
            'label': 'Excessive Subdomains',
            'detail': f"{int(features['num_subdomains'])} subdomains detected (suspicious if >3)"
        })

    if not features.get('has_https', 0):
        flags.append({
            'icon': '🔓',
            'label': 'No HTTPS Encryption',
            'detail': 'URL uses insecure HTTP protocol'
        })

    if features.get('num_special_chars', 0) > 10:
        flags.append({
            'icon': '⚡',
            'label': 'High Special Character Count',
            'detail': f"{int(features['num_special_chars'])} special characters found"
        })

    if features.get('has_double_slash', 0):
        flags.append({
            'icon': '🔀',
            'label': 'Double Slash in URL Path',
            'detail': 'Double slashes can indicate URL manipulation'
        })

    if features.get('num_at_signs', 0) > 0:
        flags.append({
            'icon': '📧',
            'label': 'At-Sign (@) in URL',
            'detail': 'The "@" symbol in URLs can be used to mislead browsers'
        })

    if features.get('digit_to_length_ratio', 0) > 0.3:
        flags.append({
            'icon': '🔢',
            'label': 'High Digit Density',
            'detail': f"{round(features['digit_to_length_ratio']*100)}% of URL is digits (obfuscation indicator)"
        })

    if features.get('url_entropy', 0) > 4.5:
        flags.append({
            'icon': '🌀',
            'label': 'High URL Entropy',
            'detail': f"Entropy: {features['url_entropy']:.2f} (randomized strings suggest obfuscation)"
        })

    if features.get('has_brand_impersonation', 0) == 1:
        flags.append({
            'icon': '🎭',
            'label': 'Brand Impersonation Detected',
            'detail': 'URL contains a trusted brand name but is NOT hosted on their official domain'
        })

    if features.get('is_shortened', 0):
        flags.append({
            'icon': '✂️',
            'label': 'URL Shortening Service Detected',
            'detail': 'Shortened URLs are frequently used to hide malicious destinations'
        })

    if features.get('has_suspicious_tld', 0):
        flags.append({
            'icon': '🚫',
            'label': 'Suspicious Top-Level Domain (TLD)',
            'detail': 'This TLD is heavily associated with spam and malware'
        })

    if features.get('vowel_consonant_ratio', 0) < 0.1 and features.get('domain_length', 0) > 8:
        flags.append({
            'icon': '🤖',
            'label': 'Algorithmic Domain Generation (DGA)',
            'detail': 'Domain lacks normal vowels, indicating it may be machine-generated'
        })

    if not flags and prediction == 'benign':
        flags.append({
            'icon': '✅',
            'label': 'No Suspicious Patterns Detected',
            'detail': 'URL appears to follow normal structural patterns'
        })

    return flags


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    load_model()
    print("\nStarting Malicious URL Detection Server...")
    port = int(os.environ.get('PORT', 7860))
    print(f"Open http://localhost:{port} in your browser\n")
    app.run(host='0.0.0.0', port=port, debug=False)
