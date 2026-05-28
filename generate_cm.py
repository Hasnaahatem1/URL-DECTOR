import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score, classification_report
import os
import time
from backend.features import extract_features
from joblib import Parallel, delayed

def load_and_preprocess(path):
    print(f"Loading dataset from {path}...")
    df = pd.read_csv(path)
    df = df.drop_duplicates(subset='url')
    df = df.dropna(subset=['url', 'type'])
    return df

def extract_single(url):
    vec, _ = extract_features(url)
    return vec

print("Loading saved model and encoder...")
model = joblib.load(os.path.join('model', 'model.pkl'))
encoder = joblib.load(os.path.join('model', 'label_encoder.pkl'))

# 1. Load Data
df = load_and_preprocess(os.path.join('data', 'malicious_phish.csv'))
y = encoder.transform(df['type'])

# 2. Split exactly like train_model.py
print("\nSplitting dataset (random_state=42)...")
_, X_test_urls, _, y_test = train_test_split(
    df['url'], y, test_size=0.2, random_state=42, stratify=y
)
print(f"Test set size: {len(X_test_urls)} URLs")

# 3. Extract features ONLY for test set (saves 80% time)
print("\nExtracting features for Test Set...")
start = time.time()
X_test = Parallel(n_jobs=-1, batch_size=1000)(
    delayed(extract_single)(url) for url in X_test_urls
)
X_test = np.array(X_test)
print(f"Feature extraction done in {time.time() - start:.1f} seconds")

# 4. Predict
print("\nPredicting on Test Set...")
y_pred = model.predict(X_test)

# 5. Metrics
print("\nRecalculating Metrics to verify:")
acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, average='weighted')
rec = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')

print(f"Accuracy:  {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall:    {rec:.4f}")
print(f"F1-Score:  {f1:.4f}")

print("\nClassification Report (Per-Class Precision & Recall):")
print(classification_report(y_test, y_pred, target_names=encoder.classes_))

# 6. Plot Confusion Matrix
print("\nGenerating final Confusion Matrix plot...")
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(10, 8))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=encoder.classes_, yticklabels=encoder.classes_)
plt.title(f'Final Model Confusion Matrix (N = {len(y_test)})')
plt.ylabel('True Class')
plt.xlabel('Predicted Class')
plt.savefig('confusion_matrix_final.png', bbox_inches='tight', dpi=300)
print("Saved to confusion_matrix_final.png")
