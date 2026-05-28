import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
import numpy as np
from features import extract_features, get_feature_names

print("Loading dataset...")
df = pd.read_csv('malicious_phish.csv')
df = df.drop_duplicates(subset='url')
df = df.dropna(subset=['url', 'type'])

# Ensure we use the exact same logic as train_model.py
# (We don't need to re-extract all 640k. We can just extract for X_test, but we need to know what X_test is.)
# Actually, since extracting 640k features takes a while, can we just extract features for a subset to get the shape of the CM?
# For an academic paper, it must be the true test set.

# Wait, we don't have the original X_test saved.
# Re-extracting features for 640k URLs takes ~2-3 minutes.
# Is there a faster way? Yes, we can just save the plot directly in a script and run it.

# Let's write the extraction logic efficiently using multiprocessing
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

def process_url(url):
    feat, _ = extract_features(str(url))
    return feat

if __name__ == '__main__':
    print("Extracting features... this will take a minute or two.")
    urls = df['url'].tolist()
    
    # We only need the test set!
    # Let's find the test set indices first.
    encoder = joblib.load('label_encoder.pkl')
    y = encoder.transform(df['type'])
    
    # We must split identically to train_model.py
    # But wait, train_model.py splits ON THE FEATURES array X, not df.
    # X and df are 1:1 mapped in train_model.py because it processes `for i, url in enumerate(df['url'])`.
    # So we can just split the URLs first!
    
    X_train_url, X_test_url, y_train, y_test = train_test_split(
        urls, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Test set size: {len(X_test_url)}")
    
    with ProcessPoolExecutor(max_workers=8) as executor:
        X_test = list(executor.map(process_url, X_test_url))
        
    X_test = np.array(X_test)
    
    print("Loading model...")
    model = joblib.load('model.pkl')
    
    print("Predicting...")
    y_pred = model.predict(X_test)
    
    cm = confusion_matrix(y_test, y_pred)
    
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=encoder.classes_, 
                yticklabels=encoder.classes_)
    plt.title('Confusion Matrix - Malicious URL Detection', fontsize=16)
    plt.ylabel('True Label', fontsize=12)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.tight_layout()
    plt.savefig('confusion_matrix.png', dpi=300)
    print("Saved to confusion_matrix.png")
    
    # Calculate Binary Matrix (Safe=benign, Malicious=others)
    # Let's find which class index is 'benign'
    benign_idx = list(encoder.classes_).index('benign')
    
    # Any prediction or true label that is NOT benign_idx is considered Malicious (1), benign is (0)
    y_test_bin = [0 if y == benign_idx else 1 for y in y_test]
    y_pred_bin = [0 if y == benign_idx else 1 for y in y_pred]
    
    from sklearn.metrics import confusion_matrix as cm_bin
    binary_matrix = cm_bin(y_test_bin, y_pred_bin)
    
    TN = binary_matrix[0][0]
    FP = binary_matrix[0][1]
    FN = binary_matrix[1][0]
    TP = binary_matrix[1][1]
    
    print("\n--- BINARY CONFUSION MATRIX ---")
    print(f"|                  | Predicted Safe | Predicted Malicious |")
    print(f"| ---------------- | -------------- | ------------------- |")
    print(f"| Actual Safe      | {TN:<14} | {FP:<19} |")
    print(f"| Actual Malicious | {FN:<14} | {TP:<19} |")
    print("-------------------------------")
