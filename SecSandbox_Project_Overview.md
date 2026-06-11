# SecSandbox Projesi: Kapsamlı Teknik Mimari ve Analiz Rehberi

Bu belge, **SecSandbox** (Security Sandbox) projesinin uçtan uca nasıl çalıştığını, hangi teknolojileri kullandığını ve oltalama (phishing) / zararlı yazılım (malware) barındıran web sitelerini tespit etmek için uyguladığı 9 aşamalı teknik işlem adımlarını hiçbir detayı atlamadan anlatmaktadır.

## 1. Projenin Amacı ve Çözdüğü Problem
Günümüzde siber saldırganlar, oltalama sitelerini ve zararlı yazılım dağıtan sayfaları gizlemek için JavaScript karmaşıklaştırma (obfuscation), gizli formlar, sahte SSL sertifikaları ve markaları taklit eden alan adları kullanmaktadırlar. 
**SecSandbox**, verilen herhangi bir URL'yi kullanıcı adına **headless (görsel arayüzü olmayan)** bir tarayıcıda çalıştırıp sayfanın ağ trafiğini, DOM yapısını, çerezlerini ve arka planda çalışan kodlarını izole bir ortamda inceleyen ve son olarak bu verileri Yapay Zeka (AI) modelleriyle değerlendiren kapsamlı bir güvenlik analiz platformudur.

---

## 2. Sistem Mimarisi ve Teknoloji Yığını
Projemiz, modüler ve ölçeklenebilir bir mikroservis mimarisine dayanmaktadır.
- **Backend API (Orchestrator):** Python tabanlı `FastAPI` framework'ü kullanılarak yazılmıştır. İstekleri karşılar, asenkron işlemleri yönetir ve tüm analiz modüllerini bir orkestra şefi gibi (`scanner.py`) sırayla çalıştırır.
- **Dinamik Tarayıcı Motoru:** `Playwright` (Asenkron Python API'si) kullanılarak Chromium tarayıcısı izole bir şekilde başlatılır.
- **Yapay Zeka Servisi (AI Inference):** NLP (Doğal Dil İşleme) ve DOM Anomali tespiti için `ai-service` adında ayrı bir mikroservis çalışır. 
- **Konteynerizasyon:** Tüm sistem `Docker` ve `docker-compose` ile izole ve üretime hazır bir şekilde çalıştırılmaktadır.

---

## 3. Çalışma Mantığı: 9 Aşamalı Analiz Boru Hattı (Pipeline)

Kullanıcı arayüzden veya eklentiden bir URL analizi başlattığında, `app/services/scanner.py` içerisindeki `run_full_scan(url)` fonksiyonu devreye girer. İşlemler sırasıyla şu şekildedir:

### AŞAMA 1: SSL/TLS Sertifika Analizi (`ssl_analyzer.py`)
İlk adımda hedefin bağlantı güvenliği incelenir.
- Sunucunun geçerli bir SSL/TLS sertifikası olup olmadığına bakılır.
- **Tespit Edilen Riskler:** Sertifika yoksa iletişimin şifrelenmediği (HTTP) uyarısı verilir. Sertifika yaşı (age_days) hesaplanır; eğer alan adı eskiyken sertifika çok yeniyse (örneğin 1-2 günlük), sitenin hacklenmiş veya yeni ele geçirilmiş olabileceği düşünülerek `caution` bayrağı kaldırılır.

### AŞAMA 2: Domain ve WHOIS Analizi (`domain_analyzer.py`)
Alan adının sicil bilgileri ve güvenilirliği incelenir.
- **WHOIS Sorgusu:** Alan adının kayıt tarihi ve bitiş tarihi çekilir. Domainin 1 yıldan (< 365 gün) daha yeni olması durumunda `Yeni Domain` uyarısı verilir. Ayrıca domainin süresinin dolmasına 30 günden az kalmışsa uyarı üretilir.
- **Kayıt Şirketi Gizliliği (Registrar Privacy):** Kayıt şirketi bilgilerinde "privacy", "proxy", "whoisguard" gibi kelimeler aranır. Oltalama siteleri genellikle kimliklerini gizlemek için bu servisleri kullandığından sistem bunu risk olarak işaretler.
- **Typosquatting (Marka Taklidi) Tespiti:** Sistem, kendi veritabanındaki (`popular_brands.csv`) popüler markalar ile URL'yi karşılaştırır. URL içerisindeki leetspeak karakterler (örneğin `0` yerine `o`, `1` yerine `i`) normalize edilir. Ardından `SequenceMatcher` kullanılarak %75 ve üzeri bir benzerlik bulunursa (fakat birebir eşleşmiyorsa), sistem **"Marka Taklidi Tespit Edildi"** uyarısı üretir (Örn: `g00gle.com`).

### AŞAMA 3: Playwright Dinamik Tarayıcı Taraması (`playwright_worker.py`)
En kritik aşamadır. Hedef URL, hiçbir kullanıcının haberi olmadan arkada `headless=True` olarak başlatılan Chromium tarayıcısında ziyaret edilir.
- **Drive-by Download Engelleme:** Sayfa açılır açılmaz bir dosya indirilmeye çalışılırsa (Örn: zararlı bir `.exe` dosyası), Playwright `on("download")` eventi tetiklenir, indirme işlemi anında **iptal edilir (BLOCKED)** ve dosyanın adı kaydedilerek yüksek risk skoru üretilir.
- **Ekran Görüntüsü (Screenshot):** Sayfanın render edilmiş halinin Base64 formatında ekran görüntüsü alınır.
- **DOM ve Metin Çıkarımı:** Sayfanın kaynak kodları ve sadece kullanıcının gördüğü görünür metinler (`innerText`) çıkarılır.
- **JavaScript Çıkarımı:** Sayfa içerisindeki (`<script>`) tüm inline kodlar ve dışarıdan yüklenen `.js` dosyalarının listesi toplanır.
- **Gizli Element Tespiti:** DOM üzerindeki tüm elementlerin CSS `getComputedStyle` değerleri kontrol edilir. Eğer bir element `display: none`, `visibility: hidden` veya `opacity: 0` değerlerine sahipse ve bu bir form veya bağlantıysa, kullanıcılardan gizlenen şüpheli bir yapı olarak listeye eklenir.
- **Form Çıkarımı:** Sayfadaki `<form>` yapıları incelenir. Formun şifre (`password`) veya e-posta (`email`) isteyip istemediği analiz edilir. Eğer form verileri bulunduğu domainden tamamen farklı bir domaine yolluyorsa (`redirects_external`), bu bir **oltalama (credential harvesting)** girişimi olarak işaretlenir.

### AŞAMA 4: İçerik ve Obfuscation (Karmaşıklaştırma) Analizi (`content_analyzer.py`)
Playwright'ın topladığı JavaScript kodları güvenlik açısından taranır.
- **Obfuscation (Kod Gizleme) Tespiti:** Zararlı yazılımlar kodlarını analizden kaçırmak için karmaşıklaştırır. Kod içerisinde regex kuralları çalıştırılır: `eval()`, `unescape()`, `String.fromCharCode()`, `atob()`, `btoa()` gibi fonksiyonların kullanımına özel risk puanları (weight) eklenir.
- **Base64 Analizi:** Kod içerisinde 500 karakterden uzun (Critical) veya 200 karakterden uzun (Suspicious) Base64 ile şifrelenmiş bloklar bulunursa tespit edilir.
- **Malicious Document.Write:** `document.write` ile dinamik olarak sayfaya `<iframe` veya `<script>` gömülüp gömülmediği kontrol edilir (False-positive oranını düşürmek için regex sadece zararlı kalıpları arar).
- **Dış Kaynak Oranı:** Sayfadaki script'lerin kaçının kendi sunucusundan, kaçının dış sunuculardan yüklendiği hesaplanır. Yüksek bir dış kaynak oranı güvensizlik göstergesi olabilir.

### AŞAMA 5: HTTP Güvenlik Başlıkları Analizi (`header_analyzer.py`)
Playwright ile yakalanan ağ trafiğindeki HTTP Response (Cevap) başlıkları incelenir. `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options` gibi güvenlik başlıklarının eksikliği durumunda siteye bir harf notu (Grade A'dan F'ye kadar) verilir.

### AŞAMA 6: Çerez (Cookie) Güvenlik Analizi (`cookie_analyzer.py`)
Tarayıcının kaydettiği tüm çerezler incelenerek güvenlik zafiyetleri tespit edilir.
- Çerezler öncelikle **Tracking (İzleyici - Google Analytics, FB vb.)** ve **Session (Oturum - auth, token, jsessionid vb.)** olarak sınıflandırılır.
- Hassas oturum çerezlerinde `HttpOnly` veya `Secure` bayraklarının (flag) olmaması XSS (Siteler Arası Betik Çalıştırma) veya veri sızıntısı riski oluşturacağından hata olarak kaydedilir.
- Çerezin yaşam süresi (Max-Age/Expires) 30 günden fazlaysa "Hassas çerezin yaşam süresi çok uzun" uyarısı üretilir. Puanlama (100 üzerinden) bulunan hata ağırlıklarına göre düşürülür.

### AŞAMA 7: Bağlantı Ağacı (Link Spider) Analizi (`link_analyzer.py`)
Sayfada tespit edilen tüm `<a>` (link) etiketleri analiz edilir.
- **Tehlikeli Dosya İndirmeleri:** Link `.exe, .msi, .bat, .apk, .scr` gibi tehlikeli uzantılara gidiyorsa riskli işaretlenir.
- **Yanıltıcı Metin (Misleading Links):** Kullanıcının gördüğü metin (Örn: `www.banka.com`) ile tıkladığında gideceği yer (`href="http://hacker.com"`) uyuşmuyorsa, bu açık bir oltalama yöntemidir ve sistem bunu tespit ederek uyarı üretir.

### AŞAMA 8: Yapay Zeka (AI) Modeli Entegrasyonu
Klasik imza tabanlı (kural tabanlı) tespitler her zaman yeterli değildir. Bu aşamada toplanan veriler XGBoost/NLP modellerine gönderilir.
- Sayfanın saf metni (maksimum 5000 karakter) alınır.
- Toplam form sayısı, dışarıya yönlenen form sayısı, gizli element sayısı ve Obfuscation skoru gibi özellikler (features) birleştirilerek bir **Feature Vector (Özellik Vektörü)** oluşturulur.
- Bu veriler arka planda çalışan `ai-service:8001` mikroservisine HTTP POST isteğiyle gönderilir.
- AI servisi iki değer döndürür: `phishing_text_risk_score` (Sayfadaki metinlerin oltalamaya ne kadar benzediği) ve `dom_anomaly_score` (Sayfa yapısındaki anormallik yüzdesi).

### AŞAMA 9: Uyarı Üretimi ve Nihai Karar (Verdict)
Tüm modüllerden gelen veriler `scanner.py` içinde birleştirilir ve toplam bir **Threat Score (Tehdit Puanı)** hesaplanır.
- Örneğin; "Drive-by download" tespit edilmişse skora anında +100 eklenir. Marka taklidi varsa +40, JS Obfuscation varsa +25 gibi ağırlıklı puanlar toplanır.
- **Skor >= 80:** Sistem `MALICIOUS (Zararlı)` uyarısı verir. Sitenin kesinlikle ziyaret edilmemesi gerektiği belirtilir.
- **Skor >= 30:** Sistem `SUSPICIOUS (Şüpheli)` uyarısı verir. Kullanıcı uyarılır.
- **Skor < 30:** Sistem `SAFE (Güvenli)` sonucunu üretir.
- Toplanan tüm veriler, bulgular ve ekran görüntüsü Pydantic şemaları (`AnalyzeResponse`) üzerinden JSON formatında Frontend arayüzüne veya tarayıcı eklentisine geri döndürülür.

---

## Sonuç
SecSandbox, geleneksel araçların aksine ağ trafiğini pasif bir şekilde dinlemekle kalmaz; aktif olarak bir Chromium tarayıcısı açarak modern oltalama tekniklerini (gizli formlar, obfuscation, drive-by indirmeler ve domain taklitleri) hem imza tabanlı hem de yapay zeka modelleriyle tespit eder. Bu doküman, uygulamanın teknik mimarisini, ölçeklenebilir altyapısını ve kapsamlı güvenlik analizi felsefesini temsil etmektedir.
