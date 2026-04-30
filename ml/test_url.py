import sys
import pickle
import numpy as np
from URLFeatureExtraction import featureExtraction
import warnings
warnings.filterwarnings("ignore")

def predict_url(url):
    print(f"Extracting features for: {url}")
    print("This might take a moment to fetch website details (Whois, Traffic, etc.)...")
    # Extract features
    features = featureExtraction(url)
    
    # The features returned by featureExtraction are 16 values
    # The model expects a 2D array, so we reshape it to (1, 16)
    features_array = np.array(features).reshape(1, -1)
    
    # Load the trained XGBoost model
    model = pickle.load(open('XGBoostClassifier.pickle.dat', 'rb'))
    
    # Make a prediction
    prediction = model.predict(features_array)[0]
    
    # In the dataset, 0 is Legitimate and 1 is Phishing
    if prediction == 1:
        print(f"\n[!] WARNING: '{url}' is detected as PHISHING! 🛑")
    else:
        print(f"\n[+] SAFE: '{url}' is detected as LEGITIMATE! ✅")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python test_url.py <URL>")
        sys.exit(1)
        
    url_to_test = sys.argv[1]
    if not url_to_test.startswith('http'):
        url_to_test = 'http://' + url_to_test
        
    predict_url(url_to_test)
