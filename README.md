# KeyCord

**Gizli Kanal, Gerçek Güvenlik** — KeyCord, Tor ağı üzerinde çalışan, gizlilik odaklı, merkeziyetsiz esinli bir mesajlaşma platformudur. Karanlık temalı arayüzünü, post-kuantum çağa hazır en modern client-side kriptografi ile birleştirir.

> **Veri Sende Kalır. Özgürce Konuş.** — KeyCord; hiçbir bilgi istemeyen bir özgürlük alanıdır.

**Gizlilik temelli değil, gizliliği inşa eden platform.** — Burada gizlilik bir hak değil, özgürlüktür. Her mesajınız, her bağlantınız özgürlüğünüzü inşa eder.

---

## 🔒 Güvenlik & Doğrulama

**Güven değil, ispat.** — Gizliliğinizi koruduğumuzu sadece iddia etmiyoruz. Bunu bağımsız güvenlik testleri ve denetlenebilir açık kaynak kodumuzla kanıtlıyoruz.

- **Mozilla Observatory:** 120/100 puan (kusursuz yapılandırma) — [Raporu İncele](https://developer.mozilla.org/en-US/observatory/analyze?host=keycord.org)
- **Security Headers:** A+ sınıfı (tam HTTP güvenlik başlıkları) — [Raporu İncele](https://securityheaders.com/?q=keycord.org&followRedirects=on)
- **GitHub Açık Kaynak:** Şifreleme motoru ve uygulama mantığı denetlenebilir — [Kodları İncele](https://github.com/Keremcm/KeyCord)

### 🛡️ Gizlilik & Güvenlik Özellikleri
- **Zero-Knowledge Mimarisi:** Özel anahtarlarınız cihazınızda oluşturulur ve saklanır. Sunucu hiçbir zaman şifrenizi veya özel anahtarlarınızı görmez.
- **Client-Side Şifreleme:** Tüm mesajlar gönderilmeden önce tarayıcıda şifrelenir; sunucu yalnızca şifreli blob'lar depolar.
- **Tor Ağında Doğal:** IP'nizi ve meta verilerinizi korumak için `.onion` adresleri için tam destek.
- **Kişisel Veri Yok:** Telefon numarası veya gerçek isim gerekli değil. Kayıt tamamen anonim, e-posta bile istenmez.
- **Trafik Analiz Direnci:** Mesaj teslimatına rastgele 1-4 saniye gecikme eklenerek meta veri analizi engellenir.
- **Reklam Yok, İzleyici Yok:** Tamamen erişilebilir ve özgür.

---

## 🔐 Uçtan Uca Şifreleme (E2EE)

- **RSA-OAEP + AES-GCM:** Mesajlar RSA-OAEP ile şifrelenmiş AES anahtarlarıyla korunur, içerik AES-GCM ile şifrelenir.
- **Post-Kuantum Hibrit (X25519 + ML-KEM-768):** Gelecekteki kuantum bilgisayar tehditlerine karşı X25519 (klasik) ve ML-KEM-768 (NIST post-kuantum standardı) anahtarları birlikte kullanılır. Hibrit anahtar çiftleri tarayıcıda üretilir, WASM modülüyle çalışır.
- **Grup & Topluluk Şifreleme:** Çoklu alıcı için `{user_id: şifreli_anahtar}` haritasıyla her üyeye ayrı şifrelenmiş anahtar dağıtılır.
- **İstemci Taraflı:** Şifreleme/decryption tamamen tarayıcıda gerçekleşir; sunucu düz metne, anahtarlara veya şifrelere hiçbir zaman erişemez.

---

## 🛰️ Savunma Katmanları (Derinlemesine Savunma)

KeyCord, tek nokta bağlılığı yerine 8 katmanlı bir middleware zinciriyle korunur:

1. **Adaptif Yük Yönetimi** — Gerçek CPU kullanımına göre tıkanma koruması: aşırı yükte istekler orantılı geciktirilir, `/api/*` 503 + Retry-After alır, WebSocket bağlantıları reddedilir, banner gösterilir.
2. **Güvenlik Middleware'i** — Global rate limiting (dakikada 400 istek), CSRF token üretimi, nonce'lı CSP + HSTS güvenlik başlıkları, CORS beyaz listesi.
3. **Giriş Güvenliği** — Giriş/kayıt için ek rate limiting (5 dakikada 10 deneme, 5 kayıt), IP bazlı kilitlenme.
4. **Girdi Temizleme** — XSS algılama ve HTML escape (kripto alanları hariç).
5. **Oturum Güvenliği** — User-Agent ve IP değişikliği algılamayla session hijacking koruması.
6. **Dosya Yükleme Güvenliği** — Uzantı + MIME tipi doğrulama, 5 MB boyut limiti.
7. **API Güvenliği** — `/api/*` uçları için daha katı rate limiting ve Bearer token zorunluluğu.
8. **Socket Güvenliği** — WebSocket bağlantıları için ayrı rate limiting ve kimlik doğrulama.

### 🍯 Honeypot & Honeytoken Sistemi
- Şüpheli yollar (`.php`, `.env`, `/wp-*`, `.git`, `.sql`, `/admin` vb.) için sahte sayfalar sunulur.
- Sahte admin giriş formlarına yerleştirilen **honeytoken** kimlik bilgileri kullanılırsa IP kalıcı olarak banlanır.
- Saldırgan girdileri Fernet şifreli olarak kaydedilir; 5 şüpheli istekte geçici, 20'de kalıcı ban uygulanır.

### 🕊️ Vazife Kanaryası (Warrant Canary)
- Yetkili makam talepleri (gizlilik ihlali / mahkeme emri) karşısında sessizce teslim olmayı kabul etmemek için `keycord_canary_warrant.txt` düzenli olarak güncellenir.

---

## 🤖 İnsan Doğrulaması (Bot Koruması)

Kayıt için çok aşamalı, botlara karşı dayanıklı bir insan doğrulaması kullanılır:

- **Proof-of-Work (PoW):** İstemci zorluğu belirtilen bir kriptografik bulmacayı çözer.
- **Simon Sıra Hafızası Oyunu:** Kullanıcı, gösterilen renk/nokta dizisini tekrarlar.
- **Tıklama Ritmi Analizi:** Ardışık tıklamalar arasındaki zamanlamayı analiz ederek script botlarını tespit eder.
- **Kademeli Zorluk:** Başarısız her denemede PoW zorluğu otomatik yükselir.

---

## 🚪 Davet-Only Kayıt

Platform, ilk kullanıcıdan sonra davet sistemiyle büyür:

- **Kişisel Davet Kodları:** Her kullanıcı en fazla 3 davet kodu oluşturabilir (30 gün geçerli).
- **Aylık Dönen Açık Davet Kodu:** Kayıt sayfasında gösterilen çok kullanımlı kod her ay yenilenir ve aylık kontenjanla sınırlıdır.
- **Master Davet Kodu:** Yönetici tarafından üretilen özel kodla sınırsız kayıt imkânı.

---

## 💬 Gerçek Zamanlı İletişim

- **Anlık Mesajlaşma:** Socket.IO ile gerçek zamanlı, E2EE şifreli DM teslimatı.
- **Anonim Teslimat:** Her mesaj alıcıya rastgele 1-4 saniyelik gecikmeyle iletilir.
- **Senkronize Bildirimler:** Mesaj, arkadaşlık isteği, grup mesajı ve duyuru bildirimleri anında itilir.
- **Gruplar:** Özel gruplar oluşturun, üye ekleyin/çıkarın, grup ayarlarını yönetin (maks. 50 üye).
- **Topluluklar:** Geniş topluluklar keşfedin, yöneticiler atayın, üyeleri yönetin, yalnızca-yönetici-sohbeti modu açın.
- **Arkadaşlık Sistemi:** Kullanıcı arama, arkadaşlık isteği gönder/kabul et/reddet.
- **Engelleme:** Kullanıcı engelleme/kaldırma.
- **Duyurular:** Platform duyuruları ve önemli uyarılar.

---

## 🎨 Arayüz & Estetik

- **Karanlık Tema:** Modern, düşük ışıklı ortamlara uygun koyu arayüz.
- **Akıcı Animasyonlar:** Anime.js ile yumuşak geçişler ve mikro-etkileşimler.
- **Yerel SVG Avatarlar:** Harici servis gerektirmeden, tamamen yerel üretilen profil resimleri.
- **Yardım Merkezi:** Makale tabanlı yardım merkezi, arama API'si ve geri bildirim formu.
- **Mobil Uyumlu:** Duyarlı düzen ile masaüstü ve mobil destek.

---

## 🌐 Çok Dilli Destek

- **Çeviriler:** Türkçe (varsayılan), İngilizce, Almanca — Flask-Babel ile.
- **Dil Algılama:** `Accept-Language` başlığından bulanık eşleşmeli otomatik dil seçimi.
- **Yasal Sayfalar:** Gizlilik Politikası, Kullanım Şartları, KVKK/GDPR, Açık Rıza Beyanı, Açık Kaynak Lisansları.

---

## 🖥️ Ayrı Landing Page

Repo içinde **bağımsız bir Flask uygulaması** olarak çalışan terminal estetikli tanıtım sayfası bulunur (`landing_page/`):

- `index.html`, `whitepaper.html` ve tam şifreleme teknik dokümanı
- Kendi rate limiting, bot engelleme ve güvenlik başlıklarıyla korunan ayrı sunucu (port 8006)
- Yol gezinme (directory traversal) koruması ve dosya türü beyaz listesi
- `/health` sağlık kontrolü uç noktası

---

## 📖 Bu Repoda Ne Var, Ne Yok?

KeyCord'un güç iddiası "koduma güven" değil "kodumu doğrula" üzerine kurulu. Bu yüzden **güveninizi doğrudan etkileyen her şey** — şifreleme motoru, mesajlaşma mantığı, savunma katmanları, honeypot sistemi — burada, açık ve denetlenebilir.

**Açık (bu repoda):**
- Client-side şifreleme motoru (`app/static/js/crypto.js`, `security.js`, `forge.min.js`, `x25519.js`, `mlkem-loader.js` — RSA-OAEP/AES-GCM + X25519 + ML-KEM-768)
- Backend uygulama mantığı (routes, models, sockets, middleware, security, utils)
- Savunma katmanları: 8 katmanlı middleware, honeypot/honeytoken, rate limiting
- Arayüz, şablonlar, çeviri dosyaları, landing page
- Genel mimari ve protokol akışı

**Kapalı (repo dışında, operasyonel nedenlerle):**
- Sunucu tarafı gizli anahtarlar (`SECRET_KEYS`, `LOG_ENCRYPTION_KEY`, JWT anahtarları)
- Çalışma zamanı verileri (kullanıcı veritabanı, oturumlar, loglar, ban listeleri)
- Sunucuya özgü dağıtım ve altyapı yapılandırması

Bu ayrım, "her şeyi görebilirsiniz ama her şeyi ifşa etmeyiz" prensibiyle çalışır — şifrelemenize güvenmeniz için doğrulama imkânınız var, ama bu doğrulama imkânı üretim sırlarını da ifşa etmiyor.

---

## 🛠️ Teknoloji Yığını

![Python](https://img.shields.io/badge/Python-3.11+-blue) ![Flask](https://img.shields.io/badge/Flask-3.1-lightgrey) ![Socket.IO](https://img.shields.io/badge/Socket.IO-5.x-black) ![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-3.x-red) ![Tor](https://img.shields.io/badge/Tor-Network-green) ![RSA](https://img.shields.io/badge/RSA-OAEP-orange) ![ML-KEM](https://img.shields.io/badge/ML--KEM--768-Post--Quantum-blueviolet)

- **Backend:** Python 3.11+ / Flask (WSGI, ProxyFix, nonce'lı CSP, HSTS)
- **Gerçek Zamanlı:** Flask-SocketIO (eventlet)
- **Veritabanı:** SQLite (WAL modu) + SQLAlchemy, Flask-Migrate (Alembic)
- **Şifreleme:** PyCryptodome (RSA-OAEP, AES-GCM), cryptography (Fernet), Forge.js + libsignal (client-side), X25519 + ML-KEM-768 WASM (post-kuantum hibrit)
- **Kimlik Doğrulama:** Flask-Login, PyJWT (Ed25519), anahtar döndürmeli özel session arayüzü, remember token'lar
- **Frontend:** Vanilla JS, CSS3 (dark theme), Jinja2, Anime.js, Socket.IO client
- **Ağ:** Tor / Onion Routing, `.onion` adresleri, Qt WebChannel (Tor browser entegrasyonu)
- **Doğrulama:** Marshmallow, python-magic (MIME), Faker (honeypot sahte verileri)
- **Uluslararasılaştırma:** Flask-Babel (tr, en, de)
- **Güvenlik Araçları:** Werkzeug (PBKDF2-SHA256), fail2ban köprüsü, dosya bütünlük izleme, IDS, IPsum tehdit istihbaratı

---


## 📄 Lisans
Bu proje **sadece görüntüleme ve inceleme amaçlıdır**. Kodların kullanımı, değiştirilmesi, dağıtılması veya herhangi bir şekilde ticari/sosyal amaçla kullanılması **yasaktır**. Tüm hakları saklıdır.

Bu lisans, projenin gizlilik ve güvenlik özelliklerini denetime açık şekilde sergilemek için GitHub'da paylaşılmasını sağlar, ancak herhangi bir kullanım izni vermez.

---

## 🤝 İletişim
- **Proje Bağlantısı:** [https://github.com/Keremcm/KeyCord](https://github.com/Keremcm/KeyCord)
- **Web Sitesi:** [https://keycord.org](https://keycord.org)
- **Tor Erişimi:** `vwu5wjocds3kpxwjpc7gy772zkwam7rtqhysumjx5t7rgizbr4mravqd.onion`
- **Instagram:** [@keycord_official](https://www.instagram.com/keycord_official)
- **E-posta:** contact@keycord.org

---
*Gizlilik ve özgürlük için geliştirildi.*
