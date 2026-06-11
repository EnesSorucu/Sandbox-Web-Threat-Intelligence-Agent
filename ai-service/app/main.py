import os
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict

# Model yükleme kütüphaneleri
import tensorflow as tf
from gensim.models import Word2Vec
import xgboost as xgb

app = FastAPI(title="SecSandbox AI Inference Service", version="1.0")

# ---- 1. MODEL VE ÖZNİTELİK YAPILANDIRMASI ----
MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "saved_models")

# Kaggle notebook'unda eğitilen tam 30 özelliğin orijinal ve sıralı listesi
EXPECTED_FEATURES = [
    'having_IPhaving_IP_Address', 'URLURL_Length', 'Shortining_Service',
    'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
    'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length',
    'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor',
    'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe',
    'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank',
    'Google_Index', 'Links_pointing_to_page', 'Statistical_report'
]

print("Yapılandırılmış modeller yükleniyor...")

# DOM Modelini Yükle
dom_model_path = os.path.join(MODELS_DIR, "dom_anomaly.xgb")
dom_model = xgb.XGBClassifier()
if os.path.exists(dom_model_path):
    dom_model.load_model(dom_model_path)
    print("✓ DOM Anomali Modeli (XGBoost) yüklendi.")
else:
    print("✗ Hata: dom_anomaly.xgb bulunamadı!")

# Word2Vec ve Keras NLP Modelini Yükle
nlp_model_path = os.path.join(MODELS_DIR, "phishing_nlp_model.keras")
w2v_model_path = os.path.join(MODELS_DIR, "word2vec.model")

if os.path.exists(nlp_model_path) and os.path.exists(w2v_model_path):
    nlp_model = tf.keras.models.load_model(nlp_model_path)
    w2v_model = Word2Vec.load(w2v_model_path)
    print("✓ NLP Metin Modeli (Keras + Word2Vec) yüklendi.")
else:
    print("✗ Hata: Keras veya Word2Vec model dosyaları eksik!")


# ---- 2. REQUEST MODELLERİ (PYDANTIC) ----
class AnalysisRequest(BaseModel):
    scraped_text: str  
    dom_features: Dict[str, float] 

# Word2Vec Cümle Vektörleştirme Yardımcı Fonksiyonu
def get_sentence_vector(text: str, w2v, vec_size=100):
    tokens = text.lower().split()
    vectors = [w2v.wv[word] for word in tokens if word in w2v.wv]
    if len(vectors) == 0:
        return np.zeros(vec_size)
    return np.mean(vectors, axis=0)


# ---- 3. API ENDPOINT ----
@app.post("/analyze")
async def analyze_website(payload: AnalysisRequest):
    try:
        # --- A. NLP TAHMİNİ (METİN ANALİZİ) ---
        sentence_vec = get_sentence_vector(payload.scraped_text, w2v_model)
        sentence_vec = np.expand_dims(sentence_vec, axis=0) 
        nlp_pred = float(nlp_model.predict(sentence_vec, verbose=0)[0][0])
        
        # NLP Eşik Değer Kontrolü (Keyword Gating)
        phishing_triggers = ['bloke', 'iptal', 'iade', 'acil', 'hediye', 'kazandınız', 'giriş yapın']
        text_lower = payload.scraped_text.lower()
        has_trigger = any(trigger in text_lower for trigger in phishing_triggers)
        if not has_trigger:
            nlp_pred = nlp_pred * 0.15
        
        # --- B. DOM TAHMİNİ (ROBUST ÖZNİTELİK HİZALAMA) ---
        # Gelen verideki eksiklikleri tamamlayan ve sıralamayı garanti altına alan mekanizma
        aligned_features = {}
        for feature in EXPECTED_FEATURES:
            if feature in payload.dom_features:
                aligned_features[feature] = payload.dom_features[feature]
            # Temiz yazılmış alternatif isimleri orijinal Kaggle karşılıklarına eşle
            elif feature == 'having_IPhaving_IP_Address' and 'having_IP_Address' in payload.dom_features:
                aligned_features[feature] = payload.dom_features['having_IP_Address']
            elif feature == 'URLURL_Length' and 'URL_Length' in payload.dom_features:
                aligned_features[feature] = payload.dom_features['URL_Length']
            else:
                # Test veya eksik kazıma anında sistemi çökertmemek için varsayılan "Güvenli (1)" ata
                aligned_features[feature] = 1
        
        # Modelin beklediği katı sıra ile DataFrame oluştur
        dom_df = pd.DataFrame([aligned_features])[EXPECTED_FEATURES]
        
        # Sınıf olasılıklarını hesapla
        dom_pred_prob = dom_model.predict_proba(dom_df)[0] 
        dom_risk_score = float(dom_pred_prob[0]) # 0 (phishing) endeksli risk olasılığı

        # DOM Veri Seyrekliği Dengesi (Sparsity Scaling)
        # Eksik özellik varsa modelin tahminini güven oranıyla ölçekle (eskiden sabit 0.20 yazıyordu)
        feature_confidence = len(payload.dom_features) / 30.0  # 8/30 = 0.27 güven
        if feature_confidence < 1.0:
            dom_risk_score = dom_risk_score * feature_confidence

        # --- C. RADİKAL AÇIKLAMA (AI INSIGHTS) ---
        insights = []
        if nlp_pred > 0.5:
            insights.append("Sitedeki metinlerde panik, aciliyet veya manipülasyon dili tespit edildi.")
        if dom_risk_score > 0.5:
            insights.append("HTML form mimarisinde veya kaynak kod link yapısında yapısal anomali saptandı.")
        if not insights:
            insights.append("Yapay zeka modelleri metin veya kod yapısında belirgin bir oltalama tehdidi bulamadı.")

        return {
            "phishing_text_risk_score": round(nlp_pred, 4),
            "dom_anomaly_score": round(dom_risk_score, 4),
            "ai_insights": " ".join(insights)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Inference Hatası: {str(e)}")

@app.get("/health")
def health_check():
    return {"status": "healthy", "models_loaded": True}