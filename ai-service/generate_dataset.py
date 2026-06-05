import csv
import random

def generate_phishing_dataset(num_samples=500):
    greetings = ["Sayın müşterimiz,", "Değerli kullanıcımız,", "Dikkat:", "Acil Bildirim:", "Önemli uyarı:", ""]
    subjects = ["banka hesabınız", "kredi kartınız", "e-devlet şifreniz", "kargo paketiniz", "Netflix üyeliğiniz", "Apple kimliğiniz", "vergi borcunuz", "aidat iadeniz", "kripto cüzdanınız", "sosyal medya hesabınız"]
    issues = ["güvenlik nedeniyle donduruldu.", "şüpheli işlem sebebiyle bloke oldu.", "süresi dolduğu için askıya alındı.", "üzerinde haciz işlemi başlatıldı.", "için iade tutarı onaylandı.", "limitiniz aşıldı.", "farklı bir cihazdan giriş yapıldı.", "teslim edilemediğinden geri dönüyor.", "çekilişten büyük ödül kazandınız.", "hakkında suç duyurusu yapıldı."]
    actions = ["Hemen hesabınızı doğrulamak için", "Ödülünüzü teslim almak için", "Blokeyi kaldırmak için", "Kargonuzu yeniden yönlendirmek için", "Cezai işlemden kaçınmak için", "İadenizi hesabınıza aktarmak için", "Güvenliğinizi sağlamak için", "Hesap dökümünüzü incelemek için", "Borcunuzu hemen ödemek için", "Şifrenizi sıfırlamak için"]
    link_prompts = ["aşağıdaki linke tıklayın.", "sisteme giriş yapın.", "bağlantıya gidin.", "bu adresi ziyaret edin.", "formu doldurun.", "hemen buraya tıklayın.", "uygulamamıza giriş yapın.", "verilen adrese gidin.", "işlemi tamamlayın.", "kimliğinizi doğrulayın."]

    sentences = set()
    while len(sentences) < num_samples:
        parts = [
            random.choice(greetings),
            random.choice(subjects),
            random.choice(issues),
            random.choice(actions),
            random.choice(link_prompts)
        ]
        # Remove empty strings and join
        sentence = " ".join([p for p in parts if p]).strip()
        sentences.add(sentence)
    
    return [[s, 1] for s in sentences]

def generate_legit_dataset(num_samples=500):
    greetings = ["Sayın müşterimiz,", "Değerli yatırımcımız,", "Merhaba,", "Bilinçli Tüketici,", "Sayın Üyemiz,", ""]
    subjects = ["aylık hesap özetiniz", "yeni ürün kampanyamız", "gizlilik politikamız", "finansal raporlarımız", "kargo takip numaranız", "müşteri hizmetleri numaramız", "şube çalışma saatlerimiz", "mobil uygulamamız", "randevu detaylarınız", "sipariş faturanız"]
    issues = ["e-posta adresinize gönderilmiştir.", "web sitemizde güncellenmiştir.", "başarıyla sisteme kaydedildi.", "hakkında detaylı bilgiyi şubelerimizden alabilirsiniz.", "ile ilgili süreç tamamlanmıştır.", "için teşekkür ederiz.", "sistemlerimizde güvenle saklanmaktadır.", "hakkında sıkça sorulan sorulara sitemizden ulaşabilirsiniz.", "belirtilen adrese teslim edilecektir.", "uygulamamız üzerinden görüntülenebilir."]
    actions = ["Daha fazla bilgi almak isterseniz", "İşlemlerinizi hızlıca yapmak için", "Kampanyaları incelemek için", "Kurumsal politikalarımızı okumak için", "İletişim formunu doldurarak", "Mobil uygulamamızı indirerek", "Müşteri temsilcimize bağlanarak", "İnternet şubemizi kullanarak", "Detaylı dokümanları indirmek için", "Öneri ve şikayetleriniz için"]
    link_prompts = ["resmi web sitemizi ziyaret edebilirsiniz.", "çağrı merkezimizi arayabilirsiniz.", "şubelerimize bekleriz.", "uygulamamızı mağazalardan güncelleyebilirsiniz.", "bizimle iletişime geçebilirsiniz.", "kurumsal sayfalarımızı inceleyebilirsiniz.", "size yardımcı olmaktan memnuniyet duyarız.", "mesai saatleri içinde arayabilirsiniz.", "destek ekibimize yazabilirsiniz.", "sistemimize güvenle giriş yapabilirsiniz."]

    sentences = set()
    while len(sentences) < num_samples:
        parts = [
            random.choice(greetings),
            random.choice(subjects),
            random.choice(issues),
            random.choice(actions),
            random.choice(link_prompts)
        ]
        # Remove empty strings and join
        sentence = " ".join([p for p in parts if p]).strip()
        sentences.add(sentence)
    
    return [[s, 0] for s in sentences]

def main():
    phishing_data = generate_phishing_dataset(500)
    legit_data = generate_legit_dataset(500)
    
    dataset = phishing_data + legit_data
    random.shuffle(dataset)

    output_file = 'turkish_phishing_dataset.csv'
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['text', 'label']) # 1 for phishing, 0 for legitimate
        writer.writerows(dataset)
        
    print(f"Dataset generated successfully at {output_file}")

if __name__ == "__main__":
    main()
