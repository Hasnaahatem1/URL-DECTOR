import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import pandas as pd
import numpy as np
import joblib
import json
import os
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score
)
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from features import extract_features, get_feature_names

# ─── Paths (all resolved relative to this script's location) ─────────────────
_HERE        = os.path.dirname(os.path.abspath(__file__))
_ROOT        = os.path.join(_HERE, '..')            # project root
DATASET_PATH = os.path.join(_ROOT, 'data',  'malicious_phish.csv')
MODEL_PATH   = os.path.join(_ROOT, 'model', 'model.pkl')
ENCODER_PATH = os.path.join(_ROOT, 'model', 'label_encoder.pkl')
STATS_PATH   = os.path.join(_ROOT, 'model', 'model_stats.json')

# Make sure the model output directory exists
os.makedirs(os.path.join(_ROOT, 'model'), exist_ok=True)


def load_and_preprocess(path, sample_size=None):
    """Load and preprocess the dataset."""
    print(f"Loading dataset from {path}...")
    df = pd.read_csv(path)
    print(f"Total records: {len(df)}")
    print(f"Class distribution:\n{df['type'].value_counts()}")

    # Drop duplicates and nulls
    df = df.drop_duplicates(subset='url')
    df = df.dropna(subset=['url', 'type'])

    # Optionally sample for faster training
    if sample_size and len(df) > sample_size:
        print(f"\nSampling {sample_size} records for balanced training...")
        # Stratified sampling to maintain class balance
        df = df.groupby('type', group_keys=False).apply(
            lambda x: x.sample(min(len(x), sample_size // df['type'].nunique()), random_state=42)
        )
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\nFinal dataset size: {len(df)}")
    print(f"Class distribution after sampling:\n{df['type'].value_counts()}")
    return df


def extract_all_features(df):
    """Extract features from all URLs in the dataframe."""
    print("\nExtracting features from URLs...")
    feature_names = get_feature_names()
    
    features_list = []
    total = len(df)
    
    for i, url in enumerate(df['url']):
        if i % 10000 == 0:
            print(f"  Progress: {i}/{total} ({100*i//total}%)")
        try:
            feat_vec, _ = extract_features(str(url))
            features_list.append(feat_vec)
        except Exception as e:
            # On failure, use zero vector
            features_list.append([0] * len(feature_names))
    
    X = np.array(features_list)
    print(f"Feature matrix shape: {X.shape}")
    return X, feature_names


def train_model(X_train, y_train):
    """Train the XGBoost classifier."""
    print("\nTraining XGBoost classifier...")
    
    # Compute balanced sample weights for multi-class imbalanced data
    sample_weights = compute_sample_weight(class_weight='balanced', y=y_train)
    
    model = XGBClassifier(
        objective='multi:softprob',
        num_class=4,
        n_estimators=400,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method='hist',
        eval_metric='mlogloss',
        n_jobs=-1,
        random_state=42
    )
    
    # Pass sample_weight to strictly penalize misclassifying minority classes (Malware, Defacement)
    model.fit(X_train, y_train, sample_weight=sample_weights)
    print("Training complete.")
    return model


def evaluate_model(model, X_test, y_test, encoder, feature_names):
    """Evaluate model and save statistics."""
    print("\nEvaluating model...")
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)

    # 1. Multi-Class Metrics (as requested)
    accuracy = accuracy_score(y_test, y_pred)
    precision_weighted = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    recall_weighted = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)
    
    # AUC ROC for Multi-class
    auc_roc = roc_auc_score(y_test, y_pred_proba, multi_class='ovr')

    print(f"\n{'='*50}")
    print(f"MULTI-CLASS EVALUATION RESULTS (4 Classes)")
    print(f"{'='*50}")
    print(f"accuracy:           {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"precision_weighted: {precision_weighted:.4f}")
    print(f"recall_weighted:    {recall_weighted:.4f}")
    print(f"f1_weighted:        {f1_weighted:.4f}")
    print(f"f1_macro:           {f1_macro:.4f}")
    print(f"AUC ROC (OVR):      {auc_roc:.4f}")
    
    print(f"\nclassification_report:")
    print(classification_report(y_test, y_pred, target_names=encoder.classes_))
    
    print(f"confusion_matrix:")
    multi_cm = confusion_matrix(y_test, y_pred)
    print(multi_cm)

    # Feature importances
    importances = model.feature_importances_
    feature_importance_dict = dict(zip(feature_names, importances.tolist()))
    sorted_importances = sorted(
        feature_importance_dict.items(), key=lambda x: x[1], reverse=True
    )

    print(f"\nTop 10 Feature Importances:")
    for name, imp in sorted_importances[:10]:
        print(f"  {name:<35} {imp:.4f}")

    # Save stats
    stats = {
        'accuracy': round(accuracy, 4),
        'precision_weighted': round(precision_weighted, 4),
        'recall_weighted': round(recall_weighted, 4),
        'f1_weighted': round(f1_weighted, 4),
        'f1_macro': round(f1_macro, 4),
        'auc_roc': round(auc_roc, 4),
        'classes': encoder.classes_.tolist(),
        'feature_importance': {k: round(v, 6) for k, v in sorted_importances},
        'feature_names': feature_names,
        'training_samples': len(X_test) * 4,  # approx
        'test_samples': len(X_test),
    }

    with open(STATS_PATH, 'w') as f:
        json.dump(stats, f, indent=2)
    print(f"\nModel stats saved to {STATS_PATH}")

    return stats


def main():
    print("=" * 60)
    print("  Malicious URL Detection - Model Training")
    print("=" * 60)

    # Load data (use full dataset for best accuracy)
    df = load_and_preprocess(DATASET_PATH, sample_size=None)

    # Encode labels
    encoder = LabelEncoder()
    y = encoder.fit_transform(df['type'])
    print(f"\nLabel encoding: {dict(zip(encoder.classes_, encoder.transform(encoder.classes_)))}")

    # Extract features
    X, feature_names = extract_all_features(df)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Testing set:  {len(X_test)} samples")

    # Train model
    model = train_model(X_train, y_train)

    # Save model and encoder FIRST (before evaluation that might fail)
    BUNDLE_PATH = os.path.join(_ROOT, 'model', 'model_bundle.pkl')
    bundle = {
        'model': model,
        'encoder': encoder
    }
    joblib.dump(bundle, BUNDLE_PATH)
    print(f"\nModel and Encoder merged and saved to {BUNDLE_PATH}")
    
    # We can delete the old split files if they exist to avoid confusion
    if os.path.exists(MODEL_PATH): os.remove(MODEL_PATH)
    if os.path.exists(ENCODER_PATH): os.remove(ENCODER_PATH)

    # Evaluate
    stats = evaluate_model(model, X_test, y_test, encoder, feature_names)
    print("\n✓ Training pipeline complete!")


if __name__ == '__main__':
    main()
