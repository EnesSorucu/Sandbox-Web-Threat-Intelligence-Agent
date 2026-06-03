# SecSandbox - AI Web Security Analyzer

SecSandbox, web sitelerini güvenli ve yalıtılmış bir ortamda (headless Chromium) ziyaret ederek analiz eden, tehditleri algılayan ve detaylı raporlar sunan yapay zeka destekli bir güvenlik analiz aracıdır.

## 🛠️ Mimari ve Özellikler
*   **SSL/TLS Analizi:** Sertifika geçerliliği, yaş ve yayıncı doğrulaması.
*   **WHOIS Sorguları:** Alan adı yaş tespiti ve Typosquatting (taklit domain) koruması.
*   **Playwright Sandbox Tarama:** Sitelere otomatik girerek ekran görüntüsü alır, çerezleri, linkleri ve HTTP başlıklarını toplar.
*   **Kod & İçerik Analizi:** JavaScript gizleme (obfuscation) tespiti ve şüpheli gizli elemanların (`<iframe>`, `<input>` vb.) detaylı dökümü.
*   **Tarayıcı Eklentisi (Context Menu):** Google aramalarında veya herhangi bir web sayfasında linklere sağ tıklayıp tek hamlede siteyi analiz etme kolaylığı.

---

## 🚀 Projeyi Çalıştırma

### 1. Docker ile Kolay Başlatma (Tavsiye Edilen)
Projenin çalışması için bilgisayarınızda **Docker Desktop** kurulu olmalıdır.

Root dizininde (`SecSandbox`) terminalden şu komutu çalıştırın:
```bash
docker-compose up --build
```
Bu komut, gerekli tüm bağımlılıkları (Python, Playwright, Chromium vb.) kuracak ve web arayüzünü ayağa kaldıracaktır.

*   **Web Arayüzü:** `http://localhost:8000`

---

### 2. Chrome Eklentisini Yükleme
Sağ tık (Context Menu) entegrasyonunu tarayıcınıza eklemek için:

1. Chrome tarayıcınızda **`chrome://extensions/`** adresine gidin.
2. Sağ üst köşedeki **"Geliştirici modu"** (Developer mode) seçeneğini aktif edin.
3. Sol üstteki **"Paketlenmemiş öğe yükle"** (Load unpacked) butonuna tıklayın.
4. Proje içindeki `chrome-extension` klasörünü seçin.
5. Artık herhangi bir web sayfasında linke sağ tıklayıp **"🛡️ SecSandbox ile Analiz Et"** seçeneğiyle doğrudan tarama başlatabilirsiniz.

---

## 📁 Dosya Yapısı
*   `/frontend-api`: FastAPI backend servisleri ve HTML/CSS/JS frontend arayüzü.
*   `/chrome-extension`: Chrome uzantısı kaynak kodları.
*   `docker-compose.yml`: Docker konteyner konfigürasyonu.
