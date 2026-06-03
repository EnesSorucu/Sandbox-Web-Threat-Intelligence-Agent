# AI-Powered Sandbox Web Security Analyzer: Proje Planı ve Mimari

Bu belge, `projectsetup.txt` dosyasındaki gereksinimler doğrultusunda, yerel olarak çalışan, yapay zeka destekli web güvenlik analizörünün profesyonel dosya dizini ve mimari planını içermektedir.

## 1. Profesyonel Dosya Dizini ve Yapısı

Projeyi mikroservis mimarisine uygun olarak 3 ana klasöre (container'a) ve ortak bir `docker-compose.yml` dosyasına böleceğiz:

```text
SecurityProject/
│
├── docker-compose.yml              # Tüm servisleri ayağa kaldıracak yapılandırma
│
├── frontend-api/                   # 1. Container: UI ve Ana Backend
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py                 # FastAPI ana uygulaması ve routing
│       ├── models/                 # Pydantic modelleri (Request/Response)
│       ├── services/               # İş mantığı (AI servisiyle haberleşme vb.)
│       ├── static/                 # Statik dosyalar
│       │   ├── css/
│       │   │   └── style.css       # ✨ Glassmorphism UI stilleri (Gradient, Blur)
│       │   ├── js/
│       │   │   └── script.js       # Dinamik etkileşimler ve animasyonlar
│       │   └── img/                # Arka plan görselleri ve ikonlar
│       └── templates/              # HTML şablonları
│           ├── index.html          # Ana sayfa (URL giriş ekranı)
│           └── report.html         # Sonuç Dashboard'u (Skorlar, AI içgörüleri)
│
├── ai-service/                     # 2. Container: Yerel Yapay Zeka Modelleri
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py                 # FastAPI API (Sadece Inference için)
│       ├── models_inference/       # Model yükleme ve tahmin kodları
│       └── saved_models/           # Eğitilmiş .pt veya .h5 model dosyaları
│           ├── phishing_nlp.pt
│           └── dom_anomaly.xgb
│
└── playwright-worker/              # 3. Container: Headless Browser Worker
    ├── Dockerfile
    ├── requirements.txt
    └── app/
        ├── worker.py               # Playwright otomasyonu ve scraping
        └── analyzer.py             # İndirme, WHOIS, SSL sertifikası kontrolü
```

## 2. Kullanıcı Arayüzü (Glassmorphism UI) Özellikleri

Tasarlanacak UI, projedeki her bir özelliği görsel olarak yansıtacak şekilde premium bir deneyim sunacaktır:

1. **Ana Sayfa (URL Girişi)**: Hareketli ve derinlik hissi veren koyu/renkli bir arka plan üzerinde yarı saydam, cam efektli (backdrop-filter: blur) bir arama çubuğu.
2. **Güvenlik Skoru (Overall Score)**: 0-100% arası dinamik olarak dolan, risk durumuna göre renk değiştiren (Yeşil: Güvenli, Kırmızı: Tehlikeli) dairesel bir ilerleme çubuğu.
3. **Dinamik Uyarı Rozetleri (Badges)**: 
   - "Otomatik İndirme Engellendi" (Kırmızı parlayan rozet)
   - "Marka Taklidi Tespit Edildi" (Turuncu rozet)
   - "Yeni SSL Sertifikası" (Sarı rozet)
   *Cam panel içinde vurgulanmış bildirimler olarak tasarlanacak.*
4. **Yapay Zeka İçgörüleri (AI Model Insights)**:
   - "Phishing Text Risk Score" ve "Form Anomaly Score" için cam efektli kartlar (Card) içerisinde detaylı ilerleme çubukları (progress bars).
5. **Teknik Loglar**: DOM analizi, gizli HTML elementleri ve harici scriptlerin listelendiği, scroll edilebilen, terminal hissi veren yarı saydam bir bilgi paneli.

## 3. Doğrulama Planı (Verification Plan)

- [x] Klasör yapısının ve boş dosyaların oluşturulması. (Tamamlandı)
- [x] HTML ve Glassmorphism CSS kullanılarak, örnek verilerle UI tasarımının (Frontend) geliştirilmesi. (Tamamlandı)
- [ ] UI tamamlandıktan sonra, FastAPI backend ve diğer servislerin (Playwright ve AI API) altyapısının kodlanması.
- [ ] `docker-compose build` ve `docker-compose up` ile tüm sistemin ayağa kaldırılması ve test edilmesi.
