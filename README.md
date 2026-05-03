# KeyCord

**Gizli Kanal, Gerçek Güvenlik** — KeyCord, Tor ağı üzerinde çalışan, gizlilik odaklı, merkeziyetsiz esinli bir mesajlaşma platformudur. Benzersiz "Kağıt/El çizimi" estetiğini, en modern client-side kriptografi ile birleştirir.

![KeyCord Banner](app/static/logo.png)

> **Veri Sende Kalır. Özgürce Konuş.** — KeyCord; hiçbir bilgi istemeyen bir özgürlük alanıdır.

**Gizlilik temelli değil, gizliliği inşaa eden platform.** — Burada gizlilik bir hak değil, özgürlüktür. Her mesajınız, her bağlantınız özgürlüğünüzü inşa eder.

---

## 🔒 Güvenlik & Doğrulama

**Güven değil, ispat.** — Gizliliğinizi koruduğumuzu sadece iddia etmiyoruz. Bunu bağımsız güvenlik testleri ve tamamen açık kaynak kodumuzla kanıtlıyoruz.

- **Mozilla Observatory:** 120/100 puan (kusursuz yapılandırma) — [Raporu İncele](https://developer.mozilla.org/en-US/observatory/analyze?host=keycord.org)
- **Security Headers:** A+ sınıfı (tam HTTP güvenlik başlıkları) — [Raporu İncele](https://securityheaders.com/?q=keycord.org&followRedirects=on)
- **GitHub Açık Kaynak:** %100 denetlenebilir kod — [Kodları İncele](https://github.com/Keremcm/KeyCord)

### 🛡️ Gizlilik & Güvenlik Özellikleri
- **Zero-Knowledge Mimarisi:** Özel anahtarlarınız cihazınızda oluşturulur ve saklanır. Sunucu hiçbir zaman şifrenizi veya özel anahtarlarınızı görmez.
- **Client-Side Şifreleme:** Tüm mesajlar gönderilmeden önce tarayıcıda **RSA-OAEP** kullanılarak şifrelenir.
- **Tor Ağında Doğal:** IP'nizi ve meta verilerinizi korumak için `.onion` adresleri için tam destek.
- **Kişisel Veri Yok:** Telefon numarası veya gerçek isim gerekli değil. Kayıt tamamen anonim.
- **Log Tutmama:** Sunucu hiçbir mesajı veya meta veriyi saklamaz.
- **Reklam Yok, İzleyici Yok:** Tamamen erişilebilir ve özgür.

### 🔐 Uçtan Uca Şifreleme (E2EE)
- **RSA + AES-GCM:** Mesajlar RSA-OAEP ile AES anahtarları şifrelenir, içerik AES-GCM ile korunur.
- **Grup Şifreleme:** Grup mesajları için çoklu alıcı anahtar yönetimi.
- **İstemci Taraflı:** Şifreleme/decryption tamamen tarayıcıda gerçekleşir.

---

## 🌟 Diğer Özellikler

### 💬 Gerçek Zamanlı İletişim
- **Anlık Mesajlaşma:** Socket.IO ile gerçek zamanlı teslimat.
- **Senkronize Bildirimler:** Akıllı bildirim sistemi tüm açık sekmeler ve cihazlar arasında anında senkronize olur.
- **Gruplar & Topluluklar:** Özel gruplar oluşturun veya genel toplulukları keşfedin.
- **Arkadaş İstekleri & Duyurular:** Sosyal özellikler.

### 🎨 Benzersiz Estetik
- **Kağıt Tasarımı:** El çizimi eskizler ve organik tipografi ile minimalist "noktalı defter" arayüzü.
- **Modern Performans:** Anime.js ile akıcı animasyonlar ve mobil/desktope duyarlı düzen.

### 🌐 Çok Dilli Destek
- **Çeviriler:** Türkçe, İngilizce, Almanca (Flask-Babel ile).
- **Uluslararasılaştırma:** Tam i18n desteği.

---

## 🛠️ Teknoloji Yığını

- **Backend:** Python / Flask (WSGI, ProxyFix, CSP, Rate Limiting)
- **Gerçek Zamanlı:** Socket.IO (Flask-SocketIO)
- **Veritabanı:** SQLAlchemy (SQLite/PostgreSQL), Alembic Migrations
- **Şifreleme:** Cryptography (RSA, AES), PyCryptoDome, Forge.js (client-side)
- **Frontend:** Vanilla JS, CSS3, Jinja2 Templates, Anime.js
- **Ağ:** Tor Project / Onion Routing, .onion adresleri, Cloudflare-Tunnel
- **Güvenlik:** Werkzeug, Flask-Login, JWT, CSP Nonce, Security Headers
- **Diğer:** Flask-Babel (i18n), Flask-Migrate, Requests, Marshmallow

---

## 📄 Lisans
Bu proje **sadece görüntüleme ve inceleme amaçlıdır**. Kodların kullanımı, değiştirilmesi, dağıtılması veya herhangi bir şekilde ticari/sosyal amaçla kullanılması **yasaktır**. Tüm hakları saklıdır.

Bu lisans, projenin gizlilik ve güvenlik özelliklerini sergilemek için GitHub'da paylaşılmasını sağlar, ancak herhangi bir kullanım izni vermez.

---

## 🤝 İletişim
- **Proje Bağlantısı:** [https://github.com/Keremcm/KeyCord](https://github.com/Keremcm/KeyCord)
- **Web Sitesi:** [https://keycord.org](https://keycord.org)
- **Tor Erişimi:** `46iblsrblve4hnsl6567lwgehwh5mrony3hbfcgkenaxqphzczlb3mid.onion`
- **Instagram:** [@keycord_official](https://www.instagram.com/keycord_official)
- **E-posta:** contact@keycord.org

---
*Gizlilik ve özgürlük için ❤️ ile geliştirildi.*
