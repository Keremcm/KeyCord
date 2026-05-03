import os
import json
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from datetime import datetime

def read_encrypted_logs():
    # .env dosyasını yükle
    load_dotenv()
    
    encryption_key = os.getenv('LOG_ENCRYPTION_KEY')
    if not encryption_key:
        print("Hata: .env dosyasında LOG_ENCRYPTION_KEY bulunamadı!")
        return

    log_file = 'security.log'
    if not os.path.exists(log_file):
        print(f"Hata: {log_file} bulunamadı!")
        return

    try:
        f = Fernet(encryption_key.encode())
    except Exception as e:
        print(f"Anahtar Hatası: {str(e)}")
        return
    
    print("=" * 80)
    print("KEYCORD ŞİFRELİ GÜVENLİK LOGLARI - DETAYLI OKUMA")
    print("=" * 80)
    print()

    total_logs = 0
    successful_decrypt = 0
    failed_decrypt = 0
    errors = []
    events_by_type = {}

    with open(log_file, 'r') as file:
        for line_num, line in enumerate(file, 1):
            line = line.strip()
            if not line:
                continue
                
            if 'ENCRYPTED_EVENT:' in line:
                total_logs += 1
                try:
                    # Log satırından şifreli kısmı ayıkla
                    encrypted_part = line.split('ENCRYPTED_EVENT: ')[1].strip()
                    decrypted_data = f.decrypt(encrypted_part.encode()).decode()
                    
                    # JSON olarak parse et
                    log_entry = json.loads(decrypted_data)
                    successful_decrypt += 1
                    
                    # Event tipi sayma
                    event_type = log_entry.get('event_type', 'UNKNOWN')
                    events_by_type[event_type] = events_by_type.get(event_type, 0) + 1
                    
                    # Detaylı gösterim
                    print(f"[{successful_decrypt}] {event_type}")
                    print(f"    Zaman: {log_entry.get('timestamp', '-')}")
                    print(f"    Detay: {log_entry.get('details', '-')}")
                    print(f"    IP: {log_entry.get('ip_address', '-')}")
                    print(f"    User ID: {log_entry.get('user_id', '-')}")
                    print(f"    Line: {line_num}")
                    print("-" * 80)
                    
                except json.JSONDecodeError as e:
                    failed_decrypt += 1
                    error_msg = f"JSON Parse Hatası (Line {line_num}): {str(e)}"
                    errors.append(error_msg)
                    print(f"❌ {error_msg}")
                    print(f"   Deşifre edilen veri: {decrypted_data[:100]}...")
                    print("-" * 80)
                    
                except Exception as e:
                    failed_decrypt += 1
                    error_msg = f"Deşifre Hatası (Line {line_num}): {type(e).__name__} - {str(e)}"
                    errors.append(error_msg)
                    print(f"❌ {error_msg}")
                    print("-" * 80)
                    
            elif 'SECURITY_EVENT:' in line:
                # Şifrelenmemiş eski loglar için
                total_logs += 1
                print(f"(Eski Log) {line}")
                print("-" * 80)

    # Özet
    print()
    print("=" * 80)
    print("ÖZET")
    print("=" * 80)
    print(f"Toplam Log: {total_logs}")
    print(f"Başarıyla Deşifre: {successful_decrypt}")
    print(f"Başarısız: {failed_decrypt}")
    print()
    
    if events_by_type:
        print("Event Tiplerine Göre Dağılım:")
        for event_type, count in sorted(events_by_type.items(), key=lambda x: -x[1]):
            print(f"  - {event_type}: {count}")
    print()
    
    if errors:
        print("Hatalar:")
        for error in errors[:10]:  # İlk 10 hatayı göster
            print(f"  ⚠️  {error}")
        if len(errors) > 10:
            print(f"  ... ve {len(errors) - 10} tane daha hata")
    else:
        print("✓ Hata yok!")
    print()

if __name__ == "__main__":
    read_encrypted_logs()
