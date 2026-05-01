import os
import json
from cryptography.fernet import Fernet
from dotenv import load_dotenv

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
    
    print("-" * 50)
    print("KEYCORD ŞİFRELİ GÜVENLİK LOGLARI")
    print("-" * 50)

    with open(log_file, 'r') as file:
        for line in file:
            if 'ENCRYPTED_EVENT:' in line:
                try:
                    # Log satırından şifreli kısmı ayıkla
                    encrypted_part = line.split('ENCRYPTED_EVENT: ')[1].strip()
                    decrypted_data = f.decrypt(encrypted_part.encode()).decode()
                    
                    # JSON olarak parse et ve güzel formatla
                    log_entry = json.loads(decrypted_data)
                    print(f"[{log_entry['timestamp']}] {log_entry['event_type']}: {log_entry['details']}")
                    print(f"   IP: {log_entry['ip_address']} | User ID: {log_entry['user_id']}")
                    print("-" * 30)
                except Exception as e:
                    # Bazı loglar eski anahtarla veya şifresiz olabilir
                    pass
            elif 'SECURITY_EVENT:' in line:
                # Şifrelenmemiş eski loglar için
                print(f"(Eski Log) {line.strip()}")

if __name__ == "__main__":
    read_encrypted_logs()
