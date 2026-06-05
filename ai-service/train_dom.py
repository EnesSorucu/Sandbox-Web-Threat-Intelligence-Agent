import os
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# 1. Veri Setini Yükleme
data_path = os.path.join("data", "phishing_dom.csv")
if not os.path.exists(data_path):
    raise FileNotFoundError(f"Hata: {data_path} bulunamadı!")

df = pd.read_csv(data_path)

# 2. Gereksiz Sütunları Temizleme
if 'index' in df.columns:
    df = df.drop(columns=['index'])

# 3. Hedef Değişkeni Çevirme (-1 -> 0)
df['Result'] = np.where(df['Result'] == -1, 0, df['Result'])

X = df.drop(columns=['Result'])
y = df['Result']

# Eğitim ve Test Setlerine Bölme (%80 Eğitim, %20 Test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. XGBoost Modelini Eğitme
print("DOM Anomali Modeli eğitiliyor (XGBoost)...")
model = XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=6,
    random_state=42,
    eval_metric='logloss'
)
model.fit(X_train, y_train)

# 5. Değerlendirme
y_pred = model.predict(X_test)

print("\n================ DOM MODEL BAŞARI METRİKLERİ ================")
print(f"Accuracy Skoru: {accuracy_score(y_test, y_pred):.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))
print("=========================================================\n")

# 6. Kaydetme
os.makedirs("saved_models", exist_ok=True)
model.save_model(os.path.join("saved_models", "dom_anomaly.xgb"))
print("DOM Anomali modeli başarıyla 'saved_models/dom_anomaly.xgb' olarak kaydedildi!")