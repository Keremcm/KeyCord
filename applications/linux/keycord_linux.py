#!/usr/bin/env python3
# keycord_shell_locked.py
# Gereksinim: pip install PyQt6 PyQt6-WebEngine

import sys, os
from PyQt6.QtCore import QStandardPaths
import webbrowser
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QUrl, Qt, QEvent
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import QApplication, QMainWindow, QGraphicsBlurEffect
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile, QWebEngineSettings

# İzin verilen domaine genişlet
ALLOWED_DOMAINS = (
    "https://keycord.org",
    "https://info.keycord.org",
)

HOME_URL = "https://keycord.org"

# Özel sayfa: navigation ve popup kontrolü
class LockedPage(QWebEnginePage):
    def acceptNavigationRequest(self, url: QUrl, nav_type, is_main_frame):
        url_str = url.toString()
        # Whitelist kontrolü
        for domain in ALLOWED_DOMAINS:
            if url_str.startswith(domain):
                return False

        # Eğer whitelist dışıysa — uygulama içinde izin verme, sistem tarayıcısında aç
        try:
            webbrowser.open(url_str)
        except Exception:
            pass
        return False

    def createWindow(self, _type):
        # Popup / yeni pencere açılmasını tamamen engelle
        return None

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KeyCord")
        self.setWindowFlag(Qt.WindowType.Window, True)
        self.setWindowIcon(QIcon("logo.ico"))
        self.setMinimumSize(1000, 800)
        self.resize(1200, 800)

        # Web engine view & profil
        self.browser = QWebEngineView()
        
         # -------- KALICI PROFİL (ASIL MESELE) --------

        data_path = QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.AppDataLocation
        )
        os.makedirs(data_path, exist_ok=True)

        profile = QWebEngineProfile("KeyCordProfile", self)
        profile.setPersistentStoragePath(data_path)
        profile.setCachePath(data_path)
        profile.setPersistentCookiesPolicy(
            QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies
        )

        # 4) Özel User-Agent
        ua = "KeyCordDesktop/1.0 (Windows; PyQt6)"
        try:
            profile.setHttpUserAgent(ua)
        except Exception:
            # Bazı PyQt sürümlerinde farklı olabilir; hata çalışmayı durdurmaz
            pass

        # Page oluştur (LockedPage kullan)
        self.page = LockedPage(profile, self.browser)

        # DevTools devre dışı bırakma (bazı sürümlerde çalışmayabilir; try/except)
        try:
            self.page.setDevToolsPage(None)
        except Exception:
            pass

        self.browser.setPage(self.page)
        self.browser.setUrl(QUrl(HOME_URL))

        # Developer Extras kapatmaya çalış (ne kadar destekleniyorsa)
        try:
            self.browser.settings().setAttribute(
                QWebEngineSettings.WebAttribute.DeveloperExtrasEnabled, False
            )
        except Exception:
            pass

        # Sağ tık menüsünü kapat
        self.browser.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)

        # Merkezi widget
        self.setCentralWidget(self.browser)

        # Sayfa yüklendikten sonra JS ile gizlilik/kopya yapıştır/overlay vs. ekle
        self.browser.loadFinished.connect(self._inject_protection_js)

        # Uygulama durum değişikliklerini dinle — başka bir uygulama ön plana çıktığında tetiklenir
        try:
            inst = QGuiApplication.instance()
            if inst is not None:
                inst.applicationStateChanged.connect(self._on_application_state_changed)
        except Exception:
            pass

    # Her blur tetiklemesinde yeni efekt oluşturmak için yardımcı fonksiyonlar
    def apply_blur(self):
        try:
            # Önce mevcut efekti temizle (zorunlu)
            self.browser.setGraphicsEffect(None)
            # Yeni blur efekti oluştur
            blur = QGraphicsBlurEffect(self.browser)
            blur.setBlurRadius(28)  # Bulanıklık şiddeti (10-40 arası dene)
            self.browser.setGraphicsEffect(blur)
        except Exception:
            pass

    def clear_blur(self):
        try:
            # Efekti kaldır
            self.browser.setGraphicsEffect(None)
        except Exception:
            pass

    def _on_application_state_changed(self, state):
        # Qt.ApplicationState.ApplicationActive dışındaki durumlarda bulanıklaştır
        try:
            if state != Qt.ApplicationState.ApplicationActive:
                self.apply_blur()
            else:
                self.clear_blur()
        except Exception:
            pass

    # Pencere aktivasyon değişikliklerini de yakala (ek güvenlik)
    def event(self, event):
        try:
            if event.type() == QEvent.Type.WindowDeactivate:
                # Pencere odak dışına çıktı → bulanıklaştır
                self.apply_blur()
            elif event.type() == QEvent.Type.WindowActivate:
                # Pencere tekrar odakta → netleştir
                self.clear_blur()
        except Exception:
            pass
        return super().event(event)

    def _inject_protection_js(self, ok: bool):
        if not ok:
            return

        # Kopyala/yapıştır/selection engelleyen JS + overlay ve visibility/focus dinleme
        protection_js = r"""
        (function () {
            try {
                // CSS ile seçim kapatma
                const style = document.createElement('style');
                style.type = 'text/css';
                style.id = 'kc-protect-style';
                style.appendChild(document.createTextNode(`
                    * { -webkit-user-select: none !important; -moz-user-select: none !important; user-select: none !important; }
                    input, textarea { user-select: text !important; } /* input/textarea'larda yazı yazmaya izin ver (ör. chat) */
                    #kc-screen-warning { position: fixed; z-index: 9999999; left: 0; top: 0; right: 0; bottom: 0;
                                         display: flex; align-items: center; justify-content: center;
                                         pointer-events: none; }
                    #kc-screen-warning .box { background: rgba(0,0,0,0.75); color: white; padding: 24px; border-radius: 8px;
                                              font-family: sans-serif; font-size: 18px; pointer-events: auto; }
                    `));
                if (!document.getElementById('kc-protect-style')) document.head.appendChild(style);

                // Overlay element (başlangıçta gizli)
                if (!document.getElementById('kc-screen-warning')) {
                    const overlay = document.createElement('div');
                    overlay.id = 'kc-screen-warning';
                    overlay.style.display = 'none';
                    const box = document.createElement('div');
                    box.className = 'box';
                    box.innerText = 'Uyarı: Görünürlük değişti veya odak kaybı tespit edildi. Gizli bilgi görüntüleniyor olabilir.';
                    overlay.appendChild(box);
                    document.body.appendChild(overlay);
                }

                // Eventler: copy/cut/contextmenu/prevent selection via events
                document.addEventListener('copy', function(e){ try { e.preventDefault(); } catch(e){} });
                document.addEventListener('cut', function(e){ try { e.preventDefault(); } catch(e){} });
                document.addEventListener('contextmenu', function(e){ try { e.preventDefault(); } catch(e){} }, true);
                document.addEventListener('keydown', function(e){
                    // Ctrl/Cmd + C/X/V/A/Z/Y --- engelle (ama input/textarea'da izin ver)
                    const tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : '';
                    const allowInInput = (tag === 'input' || tag === 'textarea' || e.target && e.target.isContentEditable);
                    if (allowInInput) return;
                    if ((e.ctrlKey || e.metaKey) && ['c','x','v','a','z','y'].includes(e.key.toLowerCase())) {
                        e.stopPropagation(); e.preventDefault();
                    }
                    // PrintScreen tuşu tespiti: bazı tarayıcılarda yakalanmaz, ama denemek zararı yok
                    if (e.key === 'PrintScreen') {
                        // overlay göster
                        const ov = document.getElementById('kc-screen-warning');
                        if (ov) ov.style.display = 'flex';
                        setTimeout(()=>{ if (ov) ov.style.display = 'none'; }, 3500);
                    }
                }, true);

                // Visibility ve focus/blur: overlay göster ve kısa uyarı ver
                function showOverlay(msg) {
                    const ov = document.getElementById('kc-screen-warning');
                    if (!ov) return;
                    const box = ov.querySelector('.box');
                    if (box) box.innerText = msg;
                    ov.style.display = 'flex';
                    setTimeout(()=>{ ov.style.display = 'none'; }, 3500);
                }

                document.addEventListener('visibilitychange', function(){
                    if (document.visibilityState !== 'visible') {
                        showOverlay('Uyarı: Sayfa görünürlüğü değişti. Gizli içerik korunuyor.');
                    }
                });

                window.addEventListener('blur', function(){
                    showOverlay('Uyarı: Pencere odak dışına çıktı. Gizli içerik korunuyor.');
                });

                window.addEventListener('focus', function(){
                    // geri dönüldüğünde kısa bilgi
                    showOverlay('Pencere odaklandı.');
                });

                // Eğer sayfa içi script'ler overlay'i kaldırmaya çalışırsa yeniden ekle
                setInterval(function(){
                    if (!document.getElementById('kc-protect-style')) {
                        document.head.appendChild(style);
                    }
                    if (!document.getElementById('kc-screen-warning')) {
                        const overlay = document.createElement('div');
                        overlay.id = 'kc-screen-warning';
                        overlay.style.display = 'none';
                        const box = document.createElement('div');
                        box.className = 'box';
                        box.innerText = 'Uyarı: Görünürlük değişti veya odak kaybı tespit edildi.';
                        overlay.appendChild(box);
                        document.body.appendChild(overlay);
                    }
                }, 2000);

            } catch (err) {
                // Hata olursa sessizce geç
                console.error('KC Protect JS error', err);
            }
        })();
        """

        # JS'i sayfaya enjekte et
        try:
            self.browser.page().runJavaScript(protection_js)
        except Exception:
            pass

if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())
