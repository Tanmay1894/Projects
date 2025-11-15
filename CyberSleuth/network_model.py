import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler, MinMaxScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import warnings
import os
import glob

# Set up plotting style
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")
warnings.filterwarnings('ignore')

# Set display options
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', None)


print("Libraries imported successfully!")

def load_and_merge_csv_files(directory_path='/content/drive/MyDrive/CICIDS 2017 datasets'):

    # Get all CSV files in the directory
    csv_files = glob.glob(os.path.join(directory_path, "*.csv"))

    print(f"Found {len(csv_files)} CSV files:")
    for file in csv_files:
        print(f"  - {os.path.basename(file)}")

    # List to store individual DataFrames
    dataframes = []

    # Load each CSV file
    for file_path in csv_files:
        print(f"\nLoading {os.path.basename(file_path)}...")
        try:
            # Read CSV file
            df = pd.read_csv(file_path)

            # Add source file information
            df['Source_File'] = os.path.basename(file_path)

            # Add to list
            dataframes.append(df)

            print(f"  Shape: {df.shape}")
            print(f"  Memory usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")

        except Exception as e:
            print(f"  Error loading {file_path}: {str(e)}")

    # Merge all DataFrames
    print(f"\nMerging {len(dataframes)} DataFrames...")
    merged_df = pd.concat(dataframes, ignore_index=True)

    print(f"Final merged DataFrame shape: {merged_df.shape}")
    print(f"Total memory usage: {merged_df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")

    return merged_df

# Load and merge all CSV files
df = load_and_merge_csv_files()

print(f"\nDataset loaded successfully!")
print(f"Shape: {df.shape}")
print(f"Columns: {len(df.columns)}")



print("DATASET FEATURES OVERVIEW")

print(f"Dataset Shape: {df.shape}")
print(f"Total Features: {df.shape[1] - 1}")  # Excluding Source_File column
print(f"Total Samples: {df.shape[0]:,}")

print(df.info())

print(df.head())

print(f"\nLabel Distribution:")
print("-" * 80)
label_counts = df[' Label'].value_counts()
print("Original labels:")
for label, count in label_counts.items():
    percentage = (count / len(df)) * 100
    print(f"  {label}: {count:,} ({percentage:.2f}%)")

# Clean the dataset
print("Starting data cleaning...")
print(f"Original shape: {df.shape}")

# copy to avoid modifying the original
df_clean = df.copy()

# 1. Cleaning column names (remove leading/trailing spaces)
print("\n1. Cleaning column names...")
df_clean.columns = df_clean.columns.str.strip()
print(f"   Column names cleaned. First few columns: {list(df_clean.columns[:5])}")

# 2. Checking for and handling infinite values
print("\n2. Handling infinite values...")
inf_count = np.isinf(df_clean.select_dtypes(include=[np.number])).sum().sum()
print(f"   Found {inf_count} infinite values")

if inf_count > 0:
    # Replacing infinite values with NaN
    df_clean = df_clean.replace([np.inf, -np.inf], np.nan)
    print("   Replaced infinite values with NaN")

# 3. Checking for missing values
print("\n3. Checking missing values...")
missing_values = df_clean.isnull().sum()
missing_percent = (missing_values / len(df_clean)) * 100

print("   Missing values per column:")
for col in missing_values[missing_values > 0].index:
    print(f"     {col}: {missing_values[col]} ({missing_percent[col]:.2f}%)")

# 4. Removing irrelevant columns if they exist
print("\n4. Removing irrelevant columns...")
irrelevant_columns = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'FlowID', 'Src IP', 'Dst IP']

columns_to_remove = []
for col in irrelevant_columns:
    if col in df_clean.columns:
        columns_to_remove.append(col)

if columns_to_remove:
    df_clean = df_clean.drop(columns=columns_to_remove)
    print(f"   Removed columns: {columns_to_remove}")
else:
    print("   No irrelevant columns found to remove")

# 5. Dropping rows with missing values
print("\n5. Dropping rows with missing values...")
initial_rows = len(df_clean)
df_clean = df_clean.dropna()
final_rows = len(df_clean)
dropped_rows = initial_rows - final_rows

print(f"   Dropped {dropped_rows} rows with missing values")
print(f"   Rows remaining: {final_rows}")

# 6. Checking data types
print("\n6. Checking data types...")
print("   Data types:")
for dtype, count in df_clean.dtypes.value_counts().items():
    print(f"     {dtype}: {count} columns")

print(f"\nCleaning completed!")
print(f"Final shape: {df_clean.shape}")

# Encoding labels
print("Starting label encoding...")

# copy to avoid modifying the original
df_encoded = df_clean.copy()

# Checking unique labels
unique_labels = df_encoded['Label'].unique()
print(f"Found {len(unique_labels)} unique labels:")
for i, label in enumerate(unique_labels):
    print(f"  {i}: {label}")

# 1. Binary encoding: BENIGN = 0, all attacks = 1
print("\n1. Creating binary encoding...")
df_encoded['Label_Binary'] = (df_encoded['Label'] != 'BENIGN').astype(int)

binary_counts = df_encoded['Label_Binary'].value_counts()
print(f"   Binary label distribution:")
print(f"     BENIGN (0): {binary_counts[0]:,} samples")
print(f"     ATTACK (1): {binary_counts[1]:,} samples")

# 2. Multi-class encoding: Keeping original attack names as integers
print("\n2. Creating multi-class encoding...")
label_encoder = LabelEncoder()
df_encoded['Label_Multi'] = label_encoder.fit_transform(df_encoded['Label'])

# Creating label mapping
label_mapping = dict(zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_)))
print(f"   Multi-class label mapping:")
for label, encoded in label_mapping.items():
    print(f"     {encoded}: {label}")

multi_counts = df_encoded['Label_Multi'].value_counts().sort_index()
print(f"   Multi-class label distribution:")
for encoded, count in multi_counts.items():
    label_name = label_encoder.inverse_transform([encoded])[0]
    print(f"     {encoded} ({label_name}): {count:,} samples")

print(f"\nLabel encoding completed!")

#Standard Scaler
print("Starting feature scaling with standard scaler...")

# copy to avoid modifying the original
df_scaled = df_encoded.copy()

# Identifying numeric columns
exclude_columns = ['Label', 'Label_Binary', 'Label_Multi', 'Source_File']
numeric_columns = df_scaled.select_dtypes(include=[np.number]).columns.tolist()
numeric_columns = [col for col in numeric_columns if col not in exclude_columns]

print(f"Found {len(numeric_columns)} numeric features to scale")
print(f"Features: {numeric_columns[:10]}{'...' if len(numeric_columns) > 10 else ''}")

# Initializing scaler
scaler = StandardScaler()

# Scaling the features
print(f"Scaling features...")
df_scaled[numeric_columns] = scaler.fit_transform(df_scaled[numeric_columns])

# Show scaling statistics
print(f"\nScaling completed!")
print(f"Scaled features statistics:")
print(f"  Mean: {df_scaled[numeric_columns].mean().mean():.6f}")
print(f"  Std: {df_scaled[numeric_columns].std().mean():.6f}")
print(f"  Min: {df_scaled[numeric_columns].min().min():.6f}")
print(f"  Max: {df_scaled[numeric_columns].max().max():.6f}")

# Build features and labels, then split
exclude_columns = ['Label', 'Label_Binary', 'Label_Multi', 'Source_File']
feature_columns = [col for col in df_scaled.columns if col not in exclude_columns]

X = df_scaled[feature_columns]
y_binary = df_scaled['Label_Binary']

X_train, X_test, y_binary_train, y_binary_test = train_test_split(
    X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
)

print(f"Train shape: {X_train.shape}, Test shape: {X_test.shape}")
print(f"Class balance (train): {np.bincount(y_binary_train)}")
print(f"Class balance (test):  {np.bincount(y_binary_test)}")

# Prepare final dataset for ML training
print("Preparing data for ML training...")

# Separate features and labels
exclude_columns = ['Label', 'Label_Binary', 'Label_Multi', 'Source_File']
feature_columns = [col for col in df_scaled.columns if col not in exclude_columns]

X = df_scaled[feature_columns]
y_binary = df_scaled['Label_Binary']
y_multi = df_scaled['Label_Multi']

print(f"Feature matrix shape: {X.shape}")
print(f"Number of features: {len(feature_columns)}")
print(f"Binary labels shape: {y_binary.shape}")
print(f"Multi-class labels shape: {y_multi.shape}")

# Split the data
X_train, X_test, y_binary_train, y_binary_test, y_multi_train, y_multi_test = train_test_split(
    X, y_binary, y_multi, test_size=0.2, random_state=42, stratify=y_binary
)

print(f"\nTrain set shape: {X_train.shape}")
print(f"Test set shape: {X_test.shape}")
print(f"Train binary labels distribution: {np.bincount(y_binary_train)}")
print(f"Test binary labels distribution: {np.bincount(y_binary_test)}")

print(f"\nData preparation completed!")
print(f"Ready for ML training with {len(feature_columns)} features")

# Ensure consistent variables for saving
exclude_columns = ['Label', 'Label_Binary', 'Label_Multi', 'Source_File']
feature_columns = [col for col in df_scaled.columns if col not in exclude_columns]

# Features and labels
y_binary = df_scaled['Label_Binary']
y_multi = df_scaled['Label_Multi']
X = df_scaled[feature_columns]

# If a split exists, reuse indices; otherwise create one
try:
    X_train
    X_test
    y_binary_train
    y_binary_test
    print("Reusing existing train/test split.")
except NameError:
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_binary_train, y_binary_test = train_test_split(
        X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
    )
    print("Created new stratified train/test split.")

# Ensure multi-class splits align with feature splits
y_multi_train = y_multi.loc[X_train.index]
y_multi_test = y_multi.loc[X_test.index]

print(f"X_train: {X_train.shape}, X_test: {X_test.shape}")
print(f"y_binary_train: {y_binary_train.shape}, y_binary_test: {y_binary_test.shape}")
print(f"y_multi_train: {y_multi_train.shape}, y_multi_test: {y_multi_test.shape}")

# Save processed dataset and splits
import json

print("Saving processed dataset and splits...")

# 1) Full processed dataset
df_scaled.to_csv('CICIDS2017_processed.csv', index=False)
print("✓ Saved: CICIDS2017_processed.csv")

# 2) Feature matrices
X_train.to_csv('X_train.csv', index=False)
X_test.to_csv('X_test.csv', index=False)
print("✓ Saved: X_train.csv, X_test.csv")

# 3) Binary labels
y_binary_train.to_csv('y_binary_train.csv', index=False, header=['Label_Binary'])
y_binary_test.to_csv('y_binary_test.csv', index=False, header=['Label_Binary'])
print("✓ Saved: y_binary_train.csv, y_binary_test.csv")

# 4) Multi-class labels
y_multi_train.to_csv('y_multi_train.csv', index=False, header=['Label_Multi'])
y_multi_test.to_csv('y_multi_test.csv', index=False, header=['Label_Multi'])
print("✓ Saved: y_multi_train.csv, y_multi_test.csv")

# 5) Feature names
with open('feature_names.txt', 'w') as f:
    for feature in feature_columns:
        f.write(f"{feature}\n")
print("✓ Saved: feature_names.txt")

# 6) Label mapping
try:
    label_mapping
except NameError:
    # build from df_encoded if available
    try:
        label_mapping = {str(label): int(code) for label, code in zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_))}
    except Exception:
        # fallback from df_scaled
        classes = sorted(df_scaled['Label'].unique())
        label_mapping = {str(c): int(i) for i, c in enumerate(classes)}

# Convert any NumPy types to native Python types for JSON safety
def to_builtin(obj):
    if isinstance(obj, np.generic):
        return obj.item()
    if isinstance(obj, dict):
        return {to_builtin(k): to_builtin(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_builtin(x) for x in obj]
    return obj

label_mapping_builtin = to_builtin(label_mapping)

with open('label_mapping.json', 'w') as f:
    json.dump(label_mapping_builtin, f, indent=2)
print("✓ Saved: label_mapping.json")

print("All files saved successfully.")

!pip install xgboost

from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
import pickle # <-- Import the pickle library

# This part of the code remains the same
# It assumes X_train, y_binary_train, etc. are already defined from your previous steps.
# ======================================================================================

# Choose reduced features if available
try:
    X_train_use = X_train_red
    X_test_use = X_test_red
    print("Using reduced features (correlation-pruned).")
except NameError:
    X_train_use = X_train
    X_test_use = X_test
    print("Reduced features not found; using full feature set.")

# ======================================================================================
# Train and Evaluate Random Forest
# ======================================================================================
rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    min_samples_leaf=2,
    max_features='sqrt',
    n_jobs=-1,
    class_weight='balanced',
    random_state=42
)
print("Training Random Forest model...")
rf.fit(X_train_use, y_binary_train)
rf_pred = rf.predict(X_test_use)

print("\n=== Random Forest Results ===")
print(f"Accuracy: {accuracy_score(y_binary_test, rf_pred):.4f}")
print(f"Macro F1: {f1_score(y_binary_test, rf_pred, average='macro'):.4f}")
print("\nClassification Report:\n", classification_report(y_binary_test, rf_pred, target_names=['BENIGN','ATTACK']))
print("Confusion Matrix:\n", confusion_matrix(y_binary_test, rf_pred))


# ======================================================================================
# Train and Evaluate XGBoost
# ======================================================================================
try:
    # Compute scale_pos_weight for imbalance
    pos_weight = (y_binary_train.shape[0] - y_binary_train.sum()) / max(y_binary_train.sum(), 1)

    xgb = XGBClassifier(
        n_estimators=500,
        learning_rate=0.05,
        max_depth=6,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=1.0,
        objective='binary:logistic',
        eval_metric='logloss',
        n_jobs=-1,
        random_state=42,
        scale_pos_weight=float(pos_weight)
    )
    print("\nTraining XGBoost model...")
    xgb.fit(X_train_use, y_binary_train)
    xgb_pred = xgb.predict(X_test_use)

    print("\n=== XGBoost Results ===")
    print(f"Accuracy: {accuracy_score(y_binary_test, xgb_pred):.4f}")
    print(f"Macro F1: {f1_score(y_binary_test, xgb_pred, average='macro'):.4f}")
    print("\nClassification Report:\n", classification_report(y_binary_test, xgb_pred, target_names=['BENIGN','ATTACK']))
    print("Confusion Matrix:\n", confusion_matrix(y_binary_test, xgb_pred))

except Exception as e:
    print(f"XGBoost unavailable or failed to train: {e}")


# ======================================================================================
# MODIFICATION: Save the trained models to .pkl files
# ======================================================================================
print("\n" + "="*50)
print("SAVING TRAINED MODELS")
print("="*50)

# Save the Random Forest model
try:
    with open('random_forest_model.pkl', 'wb') as f:
        pickle.dump(rf, f)
    print("✅ Random Forest model successfully saved as 'random_forest_model.pkl'")
except NameError:
    print("❌ Could not save Random Forest model (variable 'rf' not found).")

# Save the XGBoost model
try:
    with open('xgboost_model.pkl', 'wb') as f:
        pickle.dump(xgb, f)
    print("✅ XGBoost model successfully saved as 'xgboost_model.pkl'")
except NameError:
    print("❌ Could not save XGBoost model (variable 'xgb' not found).")

#save the scaler
try:
    with open('scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    print("✅ Scaler successfully saved as 'scaler.pkl'")
except NameError:
    print("❌ Error: Could not save the scaler.")
    print("   Please ensure the scaler variable is named 'scaler' and has been fitted.")
