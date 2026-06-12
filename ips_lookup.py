import csv
import ipaddress
import bisect
from pathlib import Path

CSV_FILE = "geolocationDatabaseIPv4.csv"   # İndirdiğiniz CSV dosyasının adı
INPUT_FILE = "banned_ips.txt"                # IP listesinin olduğu dosya
OUTPUT_FILE = "banned_ips_with_location.txt" # Çıktı dosyası

def ip_to_int(ip_str: str) -> int:
    """IP adresini (IPv4) integer'a çevirir."""
    return int(ipaddress.ip_address(ip_str))

def load_ip_ranges(csv_path: str):
    """
    CSV'deki IP aralıklarını yükler.
    Her kayıt: (start_int, end_int, location_str)
    Daha sonra binary search için start_int'e göre sıralanır.
    """
    ranges = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Sadece IPv4 kayıtlarını al (isteğe bağlı)
            if row['ip_version'] != '4':
                continue
            start_int = ip_to_int(row['start_ip'])
            end_int = ip_to_int(row['end_ip'])
            # Konum bilgisini istediğiniz gibi biçimlendirin
            # Örnek: "Ülke, Şehir" veya daha detaylı
            location = f"{row['country']}, {row['city']}"
            ranges.append((start_int, end_int, location))
    # Başlangıç adresine göre sırala (binary search için)
    ranges.sort(key=lambda x: x[0])
    # Sadece başlangıç adreslerini ayrı bir listeye al (bisect için)
    starts = [r[0] for r in ranges]
    return ranges, starts

def find_location(ip_int: int, ranges, starts):
    """
    Binary search ile IP'nin hangi aralığa düştüğünü bulur.
    """
    idx = bisect.bisect_right(starts, ip_int) - 1
    if idx < 0:
        return None
    start_int, end_int, location = ranges[idx]
    if start_int <= ip_int <= end_int:
        return location
    return None

def main():
    if not Path(CSV_FILE).exists():
        print(f"Hata: {CSV_FILE} bulunamadı.")
        return
    if not Path(INPUT_FILE).exists():
        print(f"Hata: {INPUT_FILE} bulunamadı.")
        return

    print("CSV dosyası yükleniyor (bu birkaç saniye sürebilir)...")
    ranges, starts = load_ip_ranges(CSV_FILE)
    print(f"{len(ranges)} adet IP aralığı yüklendi.")

    with open(INPUT_FILE, 'r', encoding='utf-8') as f_in, \
         open(OUTPUT_FILE, 'w', encoding='utf-8') as f_out:
        for line in f_in:
            ip = line.strip()
            if not ip:
                f_out.write("\n")
                continue
            try:
                ip_int = ip_to_int(ip)
                loc = find_location(ip_int, ranges, starts)
                if loc:
                    f_out.write(f"{ip}#{loc}\n")
                else:
                    f_out.write(f"{ip}#Bulunamadı\n")
            except ValueError:
                # Geçersiz IP formatı
                f_out.write(f"{ip}#HatalıIP\n")

    print(f"İşlem tamamlandı. Sonuçlar {OUTPUT_FILE} dosyasına yazıldı.")

if __name__ == "__main__":
    main()
