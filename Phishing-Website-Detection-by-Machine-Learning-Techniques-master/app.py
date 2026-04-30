from flask import Flask, request, jsonify
import pickle
import numpy as np
import sys
import os
base_dir = os.path.dirname(os.path.abspath(__file__))
if base_dir not in sys.path:
    sys.path.append(base_dir)

from URLFeatureExtraction import featureExtraction
import warnings

warnings.filterwarnings("ignore")

app = Flask(__name__)

import os
base_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_dir, 'XGBoostClassifier.pickle.dat')

# Load the trained XGBoost model
try:
    model = pickle.load(open(model_path, 'rb'))
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

@app.route('/predict', methods=['GET', 'POST', 'OPTIONS'])
def predict():
    if request.method == 'OPTIONS':
        # Handle CORS preflight request
        response = app.make_default_options_response()
    else:
        url = request.args.get('url')
        if request.is_json:
            url = request.json.get('url', url)
            
        if not url:
            response = jsonify({'error': 'No URL provided'})
            response.status_code = 400
        elif model is None:
            response = jsonify({'error': 'Model not loaded'})
            response.status_code = 500
        else:
            try:
                # Extract features
                features = featureExtraction(url)
                features_array = np.array(features).reshape(1, -1)
                
                # Make prediction (1 = Phishing, 0 = Legitimate)
                prediction = model.predict(features_array)[0]
                is_phishing = bool(prediction == 1)
                
                response = jsonify({
                    'url': url,
                    'is_phishing': is_phishing,
                    'prediction_code': int(prediction)
                })
            except Exception as e:
                response = jsonify({'error': str(e)})
                response.status_code = 500

    # Add CORS headers so Chrome Extension can make requests
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

# Community Consensus Blocklist
community_reports = {}

@app.route('/report', methods=['POST', 'OPTIONS'])
def report():
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
    else:
        url = request.json.get('url')
        if not url:
            response = jsonify({'error': 'No URL provided'})
            response.status_code = 400
        else:
            # Increment report count
            community_reports[url] = community_reports.get(url, 0) + 1
            is_blocked = community_reports[url] >= 3  # Block if 3+ reports
            response = jsonify({'url': url, 'reports': community_reports[url], 'is_blocked': is_blocked})

    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/community_blocklist', methods=['GET'])
def get_blocklist():
    # Return sites with 3 or more reports
    blocked = [url for url, count in community_reports.items() if count >= 3]
    response = jsonify({'blocked': blocked})
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

if __name__ == '__main__':
    print("Starting Phishing Detection ML Server on http://127.0.0.1:5000 ...")
    app.run(host='127.0.0.1', port=5000)
