
# Static Data for Help Center

HELP_CATEGORIES = [
    {
        "id": "account",
        "title": "Hesap & Profil",
        "icon": "icon-user",
        "desc": "Hesap ayarları, profil düzenleme ve doğrulama.",
        "articles": [
            {"title": "İnsan Doğrulaması Nedir?", "slug": "insan-dogrulamasi"},
            {"title": "Profil Özelleştirme", "slug": "profil-ozellestirme"},
            {"title": "Hesap Silme (Wipe)", "slug": "hesap-silme"}
        ]
    },
    {
        "id": "privacy",
        "title": "Gizlilik & Güvenlik",
        "icon": "icon-lock",
        "desc": "Uçtan uca şifreleme ve Sıfır-Bilgi (Zero-Knowledge) mimarisi.",
        "articles": [
            {"title": "Uçtan Uca Şifreleme (E2EE)", "slug": "e2ee-nedir"},
            {"title": "Sıfır-Bilgi Mimarisi", "slug": "sifir-bilgi-mimarisi"},
            {"title": "Şifre Değiştirme Hakkında", "slug": "sifre-politikasi"}
        ]
    },
    {
        "id": "messaging",
        "title": "Mesajlaşma & Sosyal",
        "icon": "icon-comments",
        "desc": "Sohbetler, gruplar ve arkadaşlık sistemi.",
        "articles": [
            {"title": "Arkadaşlık Sistemi", "slug": "arkadaslik-sistemi"},
            {"title": "Gruplar ve Topluluklar", "slug": "gruplar-vs-topluluklar"}
        ]
    }
]

HELP_ARTICLES = {
    "insan-dogrulamasi": {
        "title": "İnsan Doğrulaması Nedir?",
        "category": "Hesap & Profil",
        "content": """
        <h3>Güvenlik Önceliğimizdir</h3>
        <p>KeyCord, bot trafiğini engellemek ve platform kalitesini korumak için klasik CAPTCHA sistemleri yerine özgün bir <strong>Human Verification</strong> (İnsan Doğrulaması) sistemi kullanır.</p>
        <p>Kayıt olduktan sonra karşınıza çıkan butona 10 saniye boyunca basılı tutmanız gerekir. Bu işlem:</p>
        <ul>
            <li>Otomatik yazılımların (botların) kayıt olmasını zorlaştırır.</li>
            <li>E-posta doğrulama kodlarının sunucu maliyetini ve gizlilik riskini ortadan kaldırır.</li>
            <li>Sizin gerçek bir kullanıcı olduğunuzu kanıtlar.</li>
        </ul>
        <p>Doğrulama tamamlandığında doğrudan giriş sayfasına yönlendirilirsiniz.</p>
        """
    },
    "profil-ozellestirme": {
        "title": "Profil Özelleştirme",
        "category": "Hesap & Profil",
        "content": """
        <h3>Kendinizi İfade Edin</h3>
        <p>KeyCord profilinizi diğer kullanıcıların sizi daha iyi tanıması için özelleştirebilirsiniz:</p>
        <ul>
            <li><strong>Hakkında:</strong> Profilinizde görünecek kısa bir biyografi ekleyin.</li>
            <li><strong>Oyunlar:</strong> Oynadığınız oyunları listeleyerek diğer oyuncularla eşleşin.</li>
            <li><strong>Profil Çerçevesi:</strong> Profil fotoğrafınızın etrafına şık çerçeveler ekleyerek görünümünüzü değiştirebilirsiniz.</li>
            <li><strong>Avatar:</strong> Sistem tarafından otomatik oluşturulan veya kendi yüklediğiniz görselleri kullanabilirsiniz.</li>
        </ul>
        """
    },
    "hesap-silme": {
        "title": "Hesap Silme (Full Wipe)",
        "category": "Hesap & Profil",
        "content": """
        <h3>Dijital Silinme Hakkı</h3>
        <p>KeyCord'da verileriniz size aittir. Hesabınızı sildiğinizde sistemimizde size dair hiçbir iz kalmaz:</p>
        <ol>
            <li>Tüm mesajlarınız kalıcı olarak silinir.</li>
            <li>Sahip olduğunuz topluluklar ve gruplar dağıtılır.</li>
            <li>Şifreleme anahtarlarınız cihazınızdan tamamen kaldırılır.</li>
        </ol>
        <p><strong>Uyarı:</strong> Bu işlem geri alınamaz. E2EE anahtarlarınız silindiği için eski mesajlarınıza asla tekrar erişemezsiniz.</p>
        """
    },
    "e2ee-nedir": {
        "title": "Uçtan Uca Şifreleme (E2EE)",
        "category": "Gizlilik & Güvenlik",
        "content": """
        <h3>Sadece Siz ve Alıcı</h3>
        <p>Uçtan Uca Şifreleme (End-to-End Encryption), mesajın sizin cihazınızda şifrelenip sadece alıcının cihazında çözülmesi demektir.</p>
        <p>KeyCord'da RSA ve AES algoritmaları kullanılır. Mesajlar sunucuya ulaştığında zaten şifrelenmiştir. KeyCord yöneticileri dahil hiç kimse mesajlarınızın içeriğini düz metin olarak okuyamaz.</p>
        """
    },
    "sifir-bilgi-mimarisi": {
        "title": "Sıfır-Bilgi (Zero-Knowledge) Mimarisi",
        "category": "Gizlilik & Güvenlik",
        "content": """
        <h3>Gizliliğin Ötesinde</h3>
        <p>KeyCord, <strong>Zero-Knowledge</strong> prensibiyle çalışır. Bu, sunucularımızın sizin hakkınızda minimum bilgiye sahip olduğu anlamına gelir:</p>
        <ul>
            <li><strong>Şifreler:</strong> Şifreniz asla sunucuya ham olarak gönderilmez, güçlü algoritmalarla hashlenir.</li>
            <li><strong>Metadata:</strong> Kiminle, ne zaman konuştuğunuz gibi bilgiler şifreli veya anonimleştirilmiş olarak tutulur.</li>
            <li><strong>Anahtarlar:</strong> Özel şifreleme anahtarınız sadece sizin şifrenizle çözülebilir; biz bu anahtara erişemeyiz.</li>
        </ul>
        """
    },
    "sifre-politikasi": {
        "title": "Şifre Değiştirme Hakkında",
        "category": "Gizlilik & Güvenlik",
        "content": """
        <h3>Neden Şifre Değiştirmek Zordur?</h3>
        <p>KeyCord'da şifreniz sadece giriş yapmanızı sağlamaz, aynı zamanda <strong>Özel Şifreleme Anahtarınızı (Private Key)</strong> korur.</p>
        <p>Şifrenizi değiştirdiğinizde, eski şifrenizle şifrelenmiş olan anahtarınıza erişiminiz kesilebilir. Bu da geçmişteki tüm şifreli mesajlarınızın okunamaz hale gelmesine neden olur.</p>
        <p>Güvenliğiniz ve veri bütünlüğünüz için KeyCord, klasik "şifre yenileme" yerine, anahtar güvenliğini ön planda tutan bir mimari kullanır.</p>
        """
    },
    "arkadaslik-sistemi": {
        "title": "Arkadaşlık Sistemi",
        "category": "Mesajlaşma & Sosyal",
        "content": """
        <p>KeyCord'da biriyle doğrudan mesajlaşmak (DM) için arkadaş olmanız gerekir. Arkadaşlık sistemi gizliliği korumak için çift taraflı onay gerektirir:</p>
        <ul>
            <li>Kullanıcı adını kullanarak istek gönderin.</li>
            <li>Karşı taraf kabul ettiğinde güvenli bir şifreli tünel oluşturulur.</li>
            <li>İstediğiniz zaman birini engelleyebilir veya arkadaşlıktan çıkarabilirsiniz.</li>
        </ul>
        """
    },
    "gruplar-vs-topluluklar": {
        "title": "Gruplar ve Topluluklar",
        "category": "Mesajlaşma & Sosyal",
        "content": """
        <h3>İki Farklı Alan</h3>
        <p><strong>Gruplar:</strong> Arkadaşlarınızla kurduğunuz, dışarıya kapalı ve her mesajın E2EE ile korunduğu özel alanlardır.</p>
        <p><strong>Topluluklar:</strong> Daha geniş kitlelere hitap eden, moderasyon araçlarına sahip ve büyük projeler için tasarlanmış alanlardır. Topluluklarda sadece yöneticilerin mesaj atabileceği duyuru modları bulunabilir.</p>
        """
    }
}
