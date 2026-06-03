import urllib.request
import csv
import os
from pathlib import Path

# Majestic Million is a highly reliable top 1M dataset
MAJESTIC_URL = "http://downloads.majestic.com/majestic_million.csv"
DATA_DIR = Path(__file__).parent / "data"
CSV_PATH = DATA_DIR / "popular_brands.csv"

def download_and_prepare_dataset():
    print("Dünya çapında en popüler siteler indiriliyor (Majestic Top 10k)...")
    
    DATA_DIR.mkdir(exist_ok=True)
    
    try:
        # Majestic returns a CSV file where the 3rd column (index 2) is the domain name
        req = urllib.request.Request(MAJESTIC_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8')
            
        lines = content.strip().split('\n')
        
        brands = set()
        # Skip header line, get top 10,000 domains
        count = 0
        for line in lines[1:]:
            if count >= 10000:
                break
                
            parts = line.strip().split(',')
            if len(parts) >= 3:
                domain_full = parts[2] # 3rd column is Domain
                # Sadece marka adını al (google.com -> google)
                brand_name = domain_full.split('.')[0].lower()
                
                # Çok kısa (1-2 harf) veya anlamsız domainleri filtrele
                if len(brand_name) > 2:
                    brands.add(brand_name)
                    count += 1
                    
        # Write to our internal dataset
        with open(CSV_PATH, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["brand_name"])
            for brand in sorted(brands):
                writer.writerow([brand])
                
        print(f"Başarılı! {len(brands)} adet gerçek dünya markası {CSV_PATH} konumuna kaydedildi.")
        
    except Exception as e:
        print(f"Hata oluştu: {e}")

if __name__ == "__main__":
    download_and_prepare_dataset()
