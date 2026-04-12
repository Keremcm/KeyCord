package com.example.keycord

import android.os.Bundle
import android.view.ViewGroup
import android.view.WindowManager
import android.webkit.CookieManager
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView

import android.webkit.JavascriptInterface
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import android.util.Base64
import android.util.Log
import java.security.*
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

class MainActivity : ComponentActivity() {

    companion object {
        private const val TAG = "KeyCord"
        private const val PADDING_SIZE = 128
        private const val AES_KEY_SIZE = 32
        private const val GCM_TAG_BITS = 128
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Ekran görüntüsü / kayıt engelleme (Güvenlik)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // EncryptedSharedPreferences (Android Keystore ile şifreli yerel depolama)
        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
        val sharedPrefs = EncryptedSharedPreferences.create(
            "keycord_secure_prefs",
            masterKeyAlias,
            this,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        // ============================================================
        // WebAppInterface — JavaScript Bridge (AndroidBridge)
        // Protokol: X25519 (ECDH) → SharedSecret[:32] → AES-256-GCM
        // Padding:  2-byte header (big-endian msg length) + msg + random → 128 bytes
        // ============================================================
        class WebAppInterface {

            // --- Genel Anahtar/Token Yönetimi ---

            @JavascriptInterface
            fun saveKey(keyName: String, value: String) {
                sharedPrefs.edit().putString(keyName, value).apply()
            }

            @JavascriptInterface
            fun getKey(keyName: String): String {
                return sharedPrefs.getString(keyName, "") ?: ""
            }

            @JavascriptInterface
            fun deleteKey(keyName: String) {
                sharedPrefs.edit().remove(keyName).apply()
            }

            @JavascriptInterface
            fun saveToken(token: String) {
                sharedPrefs.edit().putString("keycord_api_token", token).apply()
            }

            // --- X25519 Anahtar Üretimi ---

            @JavascriptInterface
            fun generateKeys(username: String): String {
                return try {
                    val kpg = KeyPairGenerator.getInstance("XDH")
                    val kp = kpg.generateKeyPair()

                    // Özel anahtarı EncryptedSharedPreferences'a kaydet
                    val privB64 = Base64.encodeToString(kp.private.encoded, Base64.NO_WRAP)
                    sharedPrefs.edit().putString("${username}_x25519_priv", privB64).apply()

                    // Açık anahtarı geri dön (sunucuya kaydedilmek üzere)
                    val pubB64 = Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP)
                    Log.i(TAG, "X25519 key pair generated for $username (pub length: ${pubB64.length})")
                    pubB64
                } catch (e: Exception) {
                    Log.e(TAG, "generateKeys error", e)
                    val err = JSONObject()
                    err.put("error", e.message)
                    err.toString()
                }
            }

            // --- Şifreleme (X25519 + AES-256-GCM + 128-byte Padding) ---

            @JavascriptInterface
            fun encrypt(plainText: String, recipientPubB64: String, username: String): String {
                return try {
                    val privB64 = sharedPrefs.getString("${username}_x25519_priv", null)
                        ?: return JSONObject().put("error", "No private key for $username").toString()

                    // 1. Anahtar yeniden oluşturma
                    val kf = KeyFactory.getInstance("XDH")
                    val privateKey = kf.generatePrivate(
                        java.security.spec.PKCS8EncodedKeySpec(Base64.decode(privB64, Base64.DEFAULT))
                    )
                    val recipientPubKey = kf.generatePublic(
                        X509EncodedKeySpec(Base64.decode(recipientPubB64, Base64.DEFAULT))
                    )

                    // 2. ECDH → Shared Secret
                    val ka = KeyAgreement.getInstance("XDH")
                    ka.init(privateKey)
                    ka.doPhase(recipientPubKey, true)
                    val sharedSecret = ka.generateSecret()

                    // 3. İlk 32 byte → AES-256 anahtarı (Windows/Web ile uyumlu basit derivation)
                    val aesKeyBytes = sharedSecret.copyOf(AES_KEY_SIZE)
                    val secretKey = SecretKeySpec(aesKeyBytes, "AES")

                    // 4. 128-byte Padding (2-byte header + mesaj + rastgele dolgu)
                    val data = plainText.toByteArray(Charsets.UTF_8)
                    val msgLen = data.size
                    val padded = ByteArray(PADDING_SIZE)
                    padded[0] = ((msgLen shr 8) and 0xFF).toByte()
                    padded[1] = (msgLen and 0xFF).toByte()
                    System.arraycopy(data, 0, padded, 2, minOf(msgLen, PADDING_SIZE - 2))
                    if (2 + msgLen < PADDING_SIZE) {
                        SecureRandom().nextBytes(padded.sliceArray((2 + msgLen) until PADDING_SIZE).also { rnd ->
                            System.arraycopy(rnd, 0, padded, 2 + msgLen, rnd.size)
                        })
                    }

                    // 5. AES-256-GCM Şifreleme
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
                    val iv = cipher.iv  // 12-byte IV (Android tarafından otomatik üretilir)
                    val encrypted = cipher.doFinal(padded)

                    // 6. Sonuç (JSON)
                    val result = JSONObject()
                    result.put("ciphertext", Base64.encodeToString(encrypted, Base64.NO_WRAP))
                    result.put("nonce", Base64.encodeToString(iv, Base64.NO_WRAP))
                    result.toString()
                } catch (e: Exception) {
                    Log.e(TAG, "encrypt error", e)
                    JSONObject().put("error", e.message).toString()
                }
            }

            // --- Şifre Çözme (X25519 + AES-256-GCM + 128-byte Unpadding) ---

            @JavascriptInterface
            fun decrypt(ciphertextB64: String, nonceB64: String, senderPubB64: String, username: String): String {
                return try {
                    val privB64 = sharedPrefs.getString("${username}_x25519_priv", null)
                        ?: return "Error: No private key for $username"

                    // 1. Anahtar yeniden oluşturma
                    val kf = KeyFactory.getInstance("XDH")
                    val privateKey = kf.generatePrivate(
                        java.security.spec.PKCS8EncodedKeySpec(Base64.decode(privB64, Base64.DEFAULT))
                    )
                    val senderPubKey = kf.generatePublic(
                        X509EncodedKeySpec(Base64.decode(senderPubB64, Base64.DEFAULT))
                    )

                    // 2. ECDH → Shared Secret
                    val ka = KeyAgreement.getInstance("XDH")
                    ka.init(privateKey)
                    ka.doPhase(senderPubKey, true)
                    val sharedSecret = ka.generateSecret()

                    // 3. İlk 32 byte → AES-256 anahtarı
                    val aesKeyBytes = sharedSecret.copyOf(AES_KEY_SIZE)
                    val secretKey = SecretKeySpec(aesKeyBytes, "AES")

                    // 4. AES-256-GCM Şifre Çözme
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    val gcmSpec = GCMParameterSpec(GCM_TAG_BITS, Base64.decode(nonceB64, Base64.DEFAULT))
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
                    val decryptedPadded = cipher.doFinal(Base64.decode(ciphertextB64, Base64.DEFAULT))

                    // 5. Unpadding (2-byte header → mesaj uzunluğu)
                    val msgLen = ((decryptedPadded[0].toInt() and 0xFF) shl 8) or (decryptedPadded[1].toInt() and 0xFF)
                    String(decryptedPadded, 2, msgLen, Charsets.UTF_8)
                } catch (e: Exception) {
                    Log.e(TAG, "decrypt error", e)
                    "Error: ${e.message}"
                }
            }
        }

        // ============================================================
        // WebView Yapılandırması
        // ============================================================
        setContent {
            AndroidView(factory = {
                WebView(it).apply {
                    layoutParams = ViewGroup.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.MATCH_PARENT
                    )

                    // Arka plan rengini sitenin rengine ayarla (yüklenirken beyaz flash olmasın)
                    setBackgroundColor(android.graphics.Color.parseColor("#050607"))

                    webViewClient = object : WebViewClient() {
                        // Domain kısıtlaması (Sadece KeyCord sunucusu ve bilgi sayfası)
                        override fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean {
                            val allowed = listOf(
                                "http://192.168.18.10:8005",
                                "https://info.keycord.org",
                                "https://fonts.googleapis.com",
                                "https://fonts.gstatic.com"
                            )
                            return !allowed.any { url.startsWith(it) }
                        }

                        // Bağlantı hatası durumunda kullanıcıya görünür hata sayfası göster
                        override fun onReceivedError(
                            view: WebView,
                            errorCode: Int,
                            description: String?,
                            failingUrl: String?
                        ) {
                            Log.e(TAG, "WebView error: $description (code: $errorCode) for $failingUrl")
                            // Sadece ana sayfa hatalarında hata sayfası göster (font/asset hataları için değil)
                            if (failingUrl == "http://192.168.18.10:8005/" || failingUrl == "http://192.168.18.10:8005") {
                                view.loadData(
                                    """
                                    <html>
                                    <body style="background:#050607; color:#f7f7f5; font-family:sans-serif; 
                                                 display:flex; flex-direction:column; align-items:center; 
                                                 justify-content:center; height:100vh; margin:0; text-align:center;">
                                        <h1 style="font-size:2.5rem; margin-bottom:1rem;">⚡ KeyCord</h1>
                                        <p style="color:#d7d7d6; font-size:1.2rem; max-width:300px;">
                                            Sunucuya bağlanılamıyor.<br>
                                            Aynı ağda olduğunuzdan emin olun.
                                        </p>
                                        <p style="color:#888; font-size:0.9rem; margin-top:0.5rem;">
                                            Hata: $description (Kod: $errorCode)
                                        </p>
                                        <button onclick="location.href='http://192.168.18.10:8005/'" 
                                                style="margin-top:2rem; padding:14px 36px; background:transparent; 
                                                       border:2px solid #00c3ff; color:#00c3ff; border-radius:12px; 
                                                       font-size:1.3rem; cursor:pointer;">
                                            Tekrar Dene
                                        </button>
                                    </body>
                                    </html>
                                    """.trimIndent(),
                                    "text/html", "UTF-8"
                                )
                            }
                        }

                        // Metin seçimini engelle (Güvenlik)
                        override fun onPageFinished(view: WebView, url: String) {
                            super.onPageFinished(view, url)
                            view.evaluateJavascript(
                                """
                                (function() {
                                    var s = document.body.style;
                                    s.webkitUserSelect='none';
                                    s.userSelect='none';
                                })()
                                """.trimIndent(), null
                            )
                        }
                    }

                    // Çerez ve JS desteği
                    CookieManager.getInstance().setAcceptCookie(true)
                    CookieManager.getInstance().setAcceptThirdPartyCookies(this, true)
                    settings.javaScriptEnabled = true
                    settings.domStorageEnabled = true
                    settings.databaseEnabled = true
                    settings.mediaPlaybackRequiresUserGesture = false
                    // Google Fonts CDN (HTTPS) ve yerel sunucu (HTTP) birlikte çalışsın
                    settings.mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW

                    // JavaScript Bridge'i kaydet
                    addJavascriptInterface(WebAppInterface(), "AndroidBridge")

                    // Ana sayfayı yükle
                    loadUrl("http://192.168.18.10:8005")
                }
            }, modifier = Modifier.fillMaxSize())
        }
    }
}
