
# Static Data for Help Center
# Translating content requires request context, so data is exposed via functions
# that call gettext() at request time. Slugs and ids remain untranslated.

from flask_babel import gettext


def _cat(id, title, icon, desc, articles):
    return {
        "id": id,
        "title": gettext(title),
        "icon": icon,
        "desc": gettext(desc),
        "articles": [{"title": gettext(a["title"]), "slug": a["slug"]} for a in articles],
    }


def HELP_CATEGORIES():
    return [
        _cat(
            "account",
            "Hesap & Profil",
            "icon-user",
            "Hesap ayarları, profil düzenleme ve doğrulama.",
            [
                {"title": "İnsan Doğrulaması Nedir?", "slug": "insan-dogrulamasi"},
                {"title": "Profil Özelleştirme", "slug": "profil-ozellestirme"},
                {"title": "Hesap Silme (Wipe)", "slug": "hesap-silme"},
            ],
        ),
        _cat(
            "privacy",
            "Gizlilik & Güvenlik",
            "icon-lock",
            "Uçtan uca şifreleme ve Sıfır-Bilgi (Zero-Knowledge) mimarisi.",
            [
                {"title": "Uçtan Uca Şifreleme (E2EE)", "slug": "e2ee-nedir"},
                {"title": "Sıfır-Bilgi Mimarisi", "slug": "sifir-bilgi-mimarisi"},
                {"title": "Şifre Değiştirme Hakkında", "slug": "sifre-politikasi"},
            ],
        ),
        _cat(
            "messaging",
            "Mesajlaşma & Sosyal",
            "icon-comments",
            "Sohbetler, gruplar ve arkadaşlık sistemi.",
            [
                {"title": "Arkadaşlık Sistemi", "slug": "arkadaslik-sistemi"},
                {"title": "Gruplar ve Topluluklar", "slug": "gruplar-vs-topluluklar"},
            ],
        ),
    ]


def HELP_ARTICLES():
    articles = {
        "insan-dogrulamasi": {
            "title": gettext("İnsan Doğrulaması Nedir?"),
            "category": gettext("Hesap & Profil"),
            "content": gettext("""
        <h3>Güvenlik Önceliğimizdir</h3>
        <p>KeyCord, bot trafiğini engellemek ve platform kalitesini korumak için klasik CAPTCHA sistemleri yerine özgün bir <strong>Human Verification</strong> (İnsan Doğrulaması) sistemi kullanır.</p>
        <p>Kayıt olduktan sonra karşınıza çıkan butona 10 saniye boyunca basılı tutmanız gerekir. Bu işlem:</p>
        <ul>
            <li>Otomatik yazılımların (botların) kayıt olmasını zorlaştırır.</li>
            <li>E-posta doğrulama kodlarının sunucu maliyetini ve gizlilik riskini ortadan kaldırır.</li>
            <li>Sizin gerçek bir kullanıcı olduğunuzu kanıtlar.</li>
        </ul>
        <p>Doğrulama tamamlandığında doğrudan giriş sayfasına yönlendirilirsiniz.</p>
        """),
        },
        "profil-ozellestirme": {
            "title": gettext("Profil Özelleştirme"),
            "category": gettext("Hesap & Profil"),
            "content": gettext("""
        <h3>Kendinizi İfade Edin</h3>
        <p>KeyCord profilinizi diğer kullanıcıların sizi daha iyi tanıması için özelleştirebilirsiniz:</p>
        <ul>
            <li><strong>Hakkında:</strong> Profilinizde görünecek kısa bir biyografi ekleyin.</li>
            <li><strong>Oyunlar:</strong> Oynadığınız oyunları listeleyerek diğer oyuncularla eşleşin.</li>
            <li><strong>Profil Çerçevesi:</strong> Profil fotoğrafınızın etrafına şık çerçeveler ekleyerek görünümünüzü değiştirebilirsiniz.</li>
            <li><strong>Avatar:</strong> Sistem tarafından otomatik oluşturulan veya kendi yüklediğiniz görselleri kullanabilirsiniz.</li>
        </ul>
        """),
        },
        "hesap-silme": {
            "title": gettext("Hesap Silme (Full Wipe)"),
            "category": gettext("Hesap & Profil"),
            "content": gettext("""
        <h3>Dijital Silinme Hakkı</h3>
        <p>KeyCord'da verileriniz size aittir. Hesabınızı sildiğinizde sistemimizde size dair hiçbir iz kalmaz:</p>
        <ol>
            <li>Tüm mesajlarınız kalıcı olarak silinir.</li>
            <li>Sahip olduğunuz topluluklar ve gruplar dağıtılır.</li>
            <li>Şifreleme anahtarlarınız cihazınızdan tamamen kaldırılır.</li>
        </ol>
        <p><strong>Uyarı:</strong> Bu işlem geri alınamaz. E2EE anahtarlarınız silindiği için eski mesajlarınıza asla tekrar erişemezsiniz.</p>
        """),
        },
        "e2ee-nedir": {
            "title": gettext("Uçtan Uca Şifreleme (E2EE)"),
            "category": gettext("Gizlilik & Güvenlik"),
            "content": gettext("""
        <h3>Sadece Siz ve Alıcı</h3>
        <p>Uçtan Uca Şifreleme (End-to-End Encryption), mesajın sizin cihazınızda şifrelenip sadece alıcının cihazında çözülmesi demektir.</p>
        <p>KeyCord, kuantum bilgisayarlara dayanıklı (post-quantum) X25519 ve ML-KEM-768 hibrit anahtar değişimi ile AES-256-GCM şifrelemesi kullanır. Mesajlar sunucuya ulaştığında zaten şifrelenmiştir. KeyCord yöneticileri dahil hiç kimse mesajlarınızın içeriğini düz metin olarak okuyamaz.</p>
        """),
        },
        "sifir-bilgi-mimarisi": {
            "title": gettext("Sıfır-Bilgi (Zero-Knowledge) Mimarisi"),
            "category": gettext("Gizlilik & Güvenlik"),
            "content": gettext("""
        <h3>Gizliliğin Ötesinde</h3>
        <p>KeyCord, <strong>Zero-Knowledge</strong> prensibiyle çalışır. Bu, sunucularımızın sizin hakkınızda minimum bilgiye sahip olduğu anlamına gelir:</p>
        <ul>
            <li><strong>Şifreler:</strong> Şifreniz asla sunucuya ham olarak gönderilmez, güçlü algoritmalarla hashlenir.</li>
            <li><strong>Metadata:</strong> Kiminle, ne zaman konuştuğunuz gibi bilgiler şifreli veya anonimleştirilmiş olarak tutulur.</li>
            <li><strong>Anahtarlar:</strong> Özel şifreleme anahtarınız sadece sizin şifrenizle çözülebilir; biz bu anahtara erişemeyiz.</li>
        </ul>
        """),
        },
        "sifre-politikasi": {
            "title": gettext("Şifre Değiştirme Hakkında"),
            "category": gettext("Gizlilik & Güvenlik"),
            "content": gettext("""
        <h3>Neden Şifre Değiştirmek Zordur?</h3>
        <p>KeyCord'da şifreniz sadece giriş yapmanızı sağlamaz, aynı zamanda <strong>Özel Şifreleme Anahtarınızı (Private Key)</strong> korur.</p>
        <p>Şifrenizi değiştirdiğinizde, eski şifrenizle şifrelenmiş olan anahtarınıza erişiminiz kesilebilir. Bu da geçmişteki tüm şifreli mesajlarınızın okunamaz hale gelmesine neden olur.</p>
        <p>Güvenliğiniz ve veri bütünlüğünüz için KeyCord, klasik "şifre yenileme" yerine, anahtar güvenliğini ön planda tutan bir mimari kullanır.</p>
        """),
        },
        "arkadaslik-sistemi": {
            "title": gettext("Arkadaşlık Sistemi"),
            "category": gettext("Mesajlaşma & Sosyal"),
            "content": gettext("""
        <p>KeyCord'da biriyle doğrudan mesajlaşmak (DM) için arkadaş olmanız gerekir. Arkadaşlık sistemi gizliliği korumak için çift taraflı onay gerektirir:</p>
        <ul>
            <li>Kullanıcı adını kullanarak istek gönderin.</li>
            <li>Karşı taraf kabul ettiğinde güvenli bir şifreli tünel oluşturulur.</li>
            <li>İstediğiniz zaman birini engelleyebilir veya arkadaşlıktan çıkarabilirsiniz.</li>
        </ul>
        """),
        },
        "gruplar-vs-topluluklar": {
            "title": gettext("Gruplar ve Topluluklar"),
            "category": gettext("Mesajlaşma & Sosyal"),
            "content": gettext("""
        <h3>İki Farklı Alan</h3>
        <p><strong>Gruplar:</strong> Arkadaşlarınızla kurduğunuz, dışarıya kapalı ve her mesajın E2EE ile korunduğu özel alanlardır.</p>
        <p><strong>Topluluklar:</strong> Daha geniş kitlelere hitap eden, moderasyon araçlarına sahip ve büyük projeler için tasarlanmış alanlardır. Topluluklarda sadece yöneticilerin mesaj atabileceği duyuru modları bulunabilir.</p>
        """),
        },
    }
    return articles
