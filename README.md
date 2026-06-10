# SecSandbox - AI Web Security Analyzer

SecSandbox, web sitelerini izole edilmiş ve güvenli bir headless tarayıcı (Chromium) ortamında ziyaret ederek analiz eden, olası phishing (oltalama), zararlı yazılım ve güvenlik açıklarını tespit eden **Yapay Zeka Destekli bir Web Güvenlik Analiz Platformudur.**

Bu proje, hem detaylı bir web paneli (dashboard) hem de tarayıcı deneyimini kesintiye uğratmadan linkleri taramanızı sağlayan hafif bir **Chrome Uzantısı (Extension)** içerir.

---

## 🔍 Neler Kontrol Ediliyor? (Güvenlik Analiz Detayları)

SecSandbox, girilen veya sağ tıklanan bir URL'yi şu 7 farklı güvenlik katmanında detaylıca denetler:

### 1. SSL/TLS Sertifika Güvenliği
*   **Sertifika Varlığı & Geçerliliği:** Sitenin SSL sertifikasına sahip olup olmadığı ve süresinin dolup dolmadığı denetlenir.
*   **Yayıncı (Issuer) Kontrolü:** Sertifikanın güvenilir bir otorite (örn: Let's Encrypt, DigiCert) tarafından verilip verilmediği doğrulanır.
*   **Sertifika Ömrü (Age):** Sertifikanın ne zaman oluşturulduğu ve ne kadar süresi kaldığı kontrol edilerek olası kısa ömürlü saldırgan sertifikaları taranır.

### 2. Domain & WHOIS Analizi (Typosquatting Kontrolü)
*   **Alan Adı Yaşı:** Domain'in kaç günlük olduğu tespit edilir (Yeni açılan domainler phishing için yüksek risk taşır).
*   **Marka Taklidi (Typosquatting):** Saldırganların popüler markaları taklit edip etmediği (örn: `android` kelimesini içeren meşru olmayan siteler) özel bir algoritmayla taranır.
*   **Kayıt Firması (Registrar):** Domain'in hangi aracı kurum üzerinden tescil edildiği sorgulanır.

### 3. HTTP Güvenlik Başlıkları Denetimi (Grade: A - F)
Sitenin tarayıcılar üzerindeki güvenlik koruma başlıkları incelenir ve siteye **A ile F arasında bir güvenlik notu** verilir:
*   **X-Frame-Options:** Sitenin başka siteler içine gömülerek (Clickjacking) kullanıcıların tıklamalarının çalınmasını engelleyip engellemediği kontrol edilir.
*   **X-Content-Type-Options:** Tarayıcıların MIME türlerini taklit ederek zararlı kod çalıştırmasını (`nosniff`) önleyip önlemediği kontrol edilir.
*   **Content-Security-Policy (CSP):** Sitede Cross-Site Scripting (XSS) saldırılarını engelleyen modern CSP yapısının kurulup kurulmadığı denetlenir.
*   **Strict-Transport-Security (HSTS):** Sitenin zorunlu şifreli bağlantı (HTTPS) kullanıp kullanmadığı kontrol edilir.
*   **X-XSS-Protection:** Eski nesil tarayıcılardaki XSS filtrelerinin açık olup olmadığı denetlenir.

### 4. Çerez (Cookie) Güvenliği & Takipçi Denetimi
*   **Güvenli Çerez (Secure Flag):** Çerezlerin internette şifresiz olarak aktarılıp aktarılmadığı denetlenir.
*   **HttpOnly Flag:** Çerezlerin JavaScript (XSS) saldırılarıyla çalınmaya karşı korunup korunmadığı kontrol edilir.
*   **Takipçi Çerezleri (Tracking Cookies):** Google Analytics veya benzeri reklam/takip çerezlerinin varlığı listelenir.

### 5. Bağlantı Ağacı (Link Tree / Spider) ve Zararlı Dosya Analizi
*   **İç ve Dış Link Dağılımı:** Sayfadaki tüm dahili ve harici yönlendirmeler listelenir.
*   **Zararlı Dosya ve İndirme Linkleri:** Sitede otomatik veya manuel indirme tetikleyen tehlikeli uzantılar (`.exe`, `.apk`, `.zip`, `.msi`, `.bat`, `.scr`) taranır.
*   **Yanıltıcı (Misleading) Linkler:** Ekranda yazan metin ile arkasındaki asıl link adresinin uyuşmadığı aldatıcı bağlantılar tespit edilir (Phishing tespiti için kritiktir).

### 6. Kod ve İçerik Analizi (JS Obfuscation & Gizli Öğeler)
*   **JavaScript Karartma (Obfuscation):** Saldırganların zararlı kodları gizlemek için kullandığı yöntemler (`eval`, `unescape`, `atob`, `btoa`, yoğun Base64 kod blokları) taranarak bir risk skoru çıkarılır.
*   **Gizli DOM Öğeleri (Hidden Elements):** Kullanıcıya gösterilmeyen ama arka planda çalışan gizli formlar, gizli yönlendirme linkleri, şüpheli gizli girdiler (`<input type="hidden">`) veya arka planda reklam/kod yükleyen **gizli `<iframe>` etiketleri** tespit edilerek özellikleri listelenir.

### 7. Görsel Kanıt (Headless Browser Screenshot)
*   Playwright aracılığıyla siteye arka planda girilir ve sitenin o anki gerçek tarayıcı görüntüsü yakalanarak arayüzde gösterilir. Bu sayede kullanıcı zararlı siteye tıklamadan sitenin neye benzediğini görebilir.

### 8. Yapay Zeka (AI) Destekli Tehdit Algılama (XGBoost & NLP)
*   **DOM Yapısı Analizi (XGBoost):** Geleneksel kural tabanlı sistemlerin ötesine geçerek, sitenin HTML/DOM iskeletindeki 30 farklı özelliği (Örn: gizli iframeler, şüpheli form yönlendirmeleri, IP tabanlı URL'ler, sağ tık engellemeleri) analiz eden eğitilmiş bir XGBoost makine öğrenmesi modeli kullanılır.
*   **NLP ile Metin Analizi (Deep Learning):** Sitedeki metinler Word2Vec ve Derin Öğrenme (Keras) ağı ile taranarak insanları kandırmaya yönelik (Örn: "Hesabınız askıya alındı, hemen tıklayın") manipülatif oltalama (phishing) metinleri tespit edilir.

---

## 🛠️ Mimari ve Kullanılan Teknolojiler

*   **Backend:** FastAPI (Python 3.10), Uvicorn.
*   **Headless Tarayıcı:** Playwright (Chromium).
*   **Frontend:** Vanilla HTML5, CSS3 (Modern Glassmorphism tasarım, HSL renk paleti), JavaScript (ES6+).
*   **Dağıtım:** Docker, Docker-Compose (İzole konteyner yapısı).
*   **Eklenti:** Chrome Extension Manifest V3 (Context Menu & Background Service Worker entegrasyonu).

---

## 🚀 Projeyi Çalıştırma

### 1. Docker ile Başlatma
Projenin çalışması için bilgisayarınızda **Docker Desktop** kurulu olmalıdır.

Projenin ana dizininde (`SecurityProject`) terminalden şu komutu çalıştırın:
```bash
docker-compose up --build
```
Bu komut gerekli bağımlılıkları yükleyecek ve sunucuyu başlatacaktır.

*   **Web Arayüzü adresi:** `http://localhost:8000`

### 2. Chrome Uzantısını Yükleme
Sağ tık analiz uzantısını kurmak için:

1. Chrome'da **`chrome://extensions/`** (Uzantılar) sayfasına gidin.
2. Sağ üstteki **"Geliştirici modu"** anahtarını açın.
3. Sol üstteki **"Paketlenmemiş öğe yükle"** butonuna tıklayın.
4. Bilgisayarınızdaki proje klasörünün içindeki `chrome-extension` klasörünü seçin.
5. Kurulum tamamlanmıştır. Artık internette gezinirken herhangi bir linke **sağ tıklayarak** `🛡️ SecSandbox ile Analiz Et` butonunu kullanabilirsiniz.
