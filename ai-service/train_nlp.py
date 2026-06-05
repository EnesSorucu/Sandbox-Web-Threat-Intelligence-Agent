import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from gensim.models import Word2Vec
import pickle
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense

# 1. Veri Yükleme
data_path = os.path.join("data", "turkish_phishing_dataset.csv")
if not os.path.exists(data_path):
    raise FileNotFoundError(f"Hata: {data_path} bulunamadı!")

df = pd.read_csv(data_path)

X_text = df['text'].values
y_labels = df['label'].values

# 2. Word2Vec ile Kelime Vektörlerini Eğitme
tokenized_texts = [str(text).lower().split() for text in X_text]

print("Word2Vec modeli kelime ilişkilerini öğreniyor...")
vector_size = 100
w2v_model = Word2Vec(
    sentences=tokenized_texts, 
    vector_size=vector_size, 
    window=5, 
    min_count=1, 
    workers=4
)

# Cümle vektörlerini hesaplama fonksiyonu
def get_sentence_vector(tokens, model, vec_size):
    vectors = [model.wv[word] for word in tokens if word in model.wv]
    if len(vectors) == 0:
        return np.zeros(vec_size)
    return np.mean(vectors, axis=0)

X_w2v = np.array([get_sentence_vector(tokens, w2v_model, vector_size) for tokens in tokenized_texts])

# Train / Test Bölmesi
X_train, X_test, y_train, y_test = train_test_split(X_w2v, y_labels, test_size=0.2, random_state=42)

# 3. Keras Yapay Sinir Ağı Mimarisi
print("Keras Yapay Sinir Ağı modeli kuruluyor...")
model = Sequential([
    # Giriş katmanı (Word2Vec vektör boyutu kadar: 100) ve 64 nöronlu gizli katman
    Dense(64, activation='relu', input_shape=(vector_size,)),
    # Çıkış katmanı (Phishing olasılığı için Sigmoid aktivasyonu)
    Dense(1, activation='sigmoid')
])

# Modeli derleme (Kayıp fonksiyonu ve Optimizasyon algoritması)
model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy']
)

# 4. Model Eğitimi (Keras'ın meşhur fit fonksiyonu)
print("NLP Phishing Metin Modeli eğitiliyor (Keras + Word2Vec)...")
model.fit(
    X_train, 
    y_train, 
    epochs=50, 
    batch_size=32, 
    validation_data=(X_test, y_test),
    verbose=1
)

# 5. Model Değerlendirme
loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
print("\n================ NLP MODEL BAŞARI METRİKLERİ ================")
print(f"Genel Doğruluk (Accuracy) Skoru: {accuracy:.4f}")
print(f"Test Kayıp (Loss) Skoru: {loss:.4f}")
print("=========================================================\n")

# 6. Modeli ve Word2Vec Nesnesini Kaydetme
os.makedirs("saved_models", exist_ok=True)

# Keras modelini .keras formatında kaydediyoruz
model.save(os.path.join("saved_models", "phishing_nlp_model.keras"))

# Gensim Word2Vec modelini canlı tahminlerde kullanmak üzere ayrı olarak kaydediyoruz
w2v_model.save(os.path.join("saved_models", "word2vec.model"))

print("Keras ve Word2Vec modelleri 'saved_models/' klasörüne başarıyla kaydedildi!")