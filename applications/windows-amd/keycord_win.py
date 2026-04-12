#!/usr/bin/env python3
# keycord_shell_locked.py
# Gereksinim: pip install PyQt6 PyQt6-WebEngine

import sys, os, random, json, base64
from PyQt6.QtCore import QStandardPaths, QObject, pyqtSlot
import webbrowser
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtCore import QUrl, Qt, QEvent, QTimer
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import QApplication, QMainWindow, QGraphicsBlurEffect, QSystemTrayIcon, QMenu
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile, QWebEngineSettings
from PyQt6.QtWebChannel import QWebChannel

# Native Crypto Imports
try:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM # Changed from ChaCha20Poly1305
    import keyring
except ImportError:
    pass

# İzin verilen domaine genişlet
ALLOWED_DOMAINS = (
    "https://keycord.org",
    "https://info.keycord.org",
)

HOME_URL = "https://keycord.org"

# Komik Bildirim Mesajları
NOTIFICATION_MESSAGES = [
    "Burada gizli bir mesele var!",
    "Baksan iyi olur...",
    "Pst! Sesler geliyor... ",
    "Gizli dosya ulaştı!",
    "Mesaj alındı, kendini imha etmeden oku!",
    "Birileri seni merak ediyor...",
    "Çok gizli bilgi!",
    "Buralar bir anda ısındı...",
    "Hey! Birşeyler oluyor..."
]

# Özel sayfa: navigation ve popup kontrolü
class LockedPage(QWebEnginePage):
    def acceptNavigationRequest(self, url: QUrl, nav_type, is_main_frame):
        url_str = url.toString()
        # Whitelist kontrolü
        for domain in ALLOWED_DOMAINS:
            if url_str.startswith(domain):
                return True

        # Eğer whitelist dışıysa — uygulama içinde izin verme, sistem tarayıcısında aç
        try:
            webbrowser.open(url_str)
        except Exception:
            pass
        return False

    def createWindow(self, _type):
        # Popup / yeni pencere açılmasını tamamen engelle
        return None

class KCCryptoBridge(QObject):
    """Native Bridge for X25519 Operations"""
    
    SERVICE_NAME = "KeyCord_E2EE"
    
    @pyqtSlot(str, result=str)
    def generate_keys(self, username):
        try:
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()
            
            priv_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            keyring.set_password(self.SERVICE_NAME, f"{username}_priv", base64.b64encode(priv_bytes).decode())
            
            pub_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return base64.b64encode(pub_bytes).decode()
        except Exception as e:
            return json.dumps({"error": str(e)})

    @pyqtSlot(str, str, str, result=str)
    def encrypt(self, plain_text, recipient_pub_b64, username):
        try:
            priv_b64 = keyring.get_password(self.SERVICE_NAME, f"{username}_priv")
            if not priv_b64: return json.dumps({"error": "No key"})
                
            private_key = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
            recipient_pub = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(recipient_pub_b64))
            shared_key = private_key.exchange(recipient_pub)
            
            # Simple derivation (matched with Android/Web)
            derived_key = shared_key[:32]
            nonce = os.urandom(12)
            
            # Padding (128 bytes to match JS)
            data = plain_text.encode('utf-8')
            msg_len = len(data)
            header = bytes([(msg_len >> 8) & 0xFF, msg_len & 0xFF])
            padded = header + data
            if len(padded) < 128:
                padded += os.urandom(128 - len(padded))
            
            aesgcm = AESGCM(derived_key)
            ciphertext = aesgcm.encrypt(nonce, padded, None)
            
            return json.dumps({
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "nonce": base64.b64encode(nonce).decode()
            })
        except Exception as e:
            return json.dumps({"error": str(e)})

    @pyqtSlot(str, str, str, str, result=str)
    def decrypt(self, ciphertext_b64, nonce_b64, sender_pub_b64, username):
        try:
            priv_b64 = keyring.get_password(self.SERVICE_NAME, f"{username}_priv")
            if not priv_b64: return json.dumps({"error": "No key"})
                
            private_key = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
            sender_pub = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(sender_pub_b64))
            shared_key = private_key.exchange(sender_pub)
            
            # Simple derivation (matched with Android/Web)
            derived_key = shared_key[:32]
            aesgcm = AESGCM(derived_key)
            
            decrypted_padded = aesgcm.decrypt(base64.b64decode(nonce_b64), base64.b64decode(ciphertext_b64), None)
            
            # Unpadding
            msg_len = (decrypted_padded[0] << 8) | decrypted_padded[1]
            return decrypted_padded[2:2+msg_len].decode('utf-8')
        except Exception as e:
            return f"Error: {str(e)}"

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KeyCord")
        self.setWindowFlag(Qt.WindowType.Window, True)
        self.setWindowIcon(QIcon("logo_black.ico"))
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

        # Native Bridge Setup
        self.crypto_bridge = KCCryptoBridge()
        self.web_channel = QWebChannel()
        self.web_channel.registerObject("crypto", self.crypto_bridge)
        self.page.setWebChannel(self.web_channel)

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

        # --- SYSTEM TRAY & NOTIFICATIONS ---
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("logo.ico"))
        
        # Tray Menu
        tray_menu = QMenu()
        show_action = QAction("Göster", self)
        show_action.triggered.connect(self.show_window)
        quit_action = QAction("Çıkış", self)
        quit_action.triggered.connect(self.quit_app)
        
        tray_menu.addAction(show_action)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_icon_activated)
        self.tray_icon.show()

        # Notification Polling Timer
        self.notification_timer = QTimer(self)
        self.notification_timer.timeout.connect(self.check_notifications)
        self.notification_timer.start(3000) # Her 3 saniyede bir kontrol et
        
        self.has_unread_notification = False # Durumu takip et

    def show_window(self):
        self.show()
        self.setWindowState(self.windowState() & ~Qt.WindowState.WindowMinimized | Qt.WindowState.WindowActive)
        self.activateWindow()

    def quit_app(self):
        self.tray_icon.hide()
        QApplication.quit()

    def on_tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.isVisible():
                self.hide()
            else:
                self.show_window()
        elif reason == QSystemTrayIcon.ActivationReason.MessageClicked:
            self.show_window()

    def closeEvent(self, event):
        # Kapatmak yerine gizle (arka planda çalışsın)
        if self.tray_icon.isVisible():
            self.hide()
            event.ignore()
            # İlk seferinde kullanıcıya bilgi verilebilir (isteğe bağlı)
            # self.tray_icon.showMessage("KeyCord", "Uygulama arka planda çalışmaya devam ediyor.", QSystemTrayIcon.MessageIcon.Information, 2000)
        else:
            event.accept()

    def check_notifications(self):
        # 1. Token'ı sayfadan almaya çalış (Eğer henüz almadıysak)
        if not hasattr(self, 'api_token') or not self.api_token:
            self.browser.page().runJavaScript(
                "document.getElementById('api-token-hidden') ? document.getElementById('api-token-hidden').value : null",
                self.set_api_token
            )
            return

        # 2. API ile kontrol et
        import urllib.request
        import json

        try:
            req = urllib.request.Request(
                f"{HOME_URL}/api/notifications",
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "User-Agent": "KeyCordDesktop/1.0"
                }
            )
            with urllib.request.urlopen(req) as response:
                if response.status == 200:
                    data = json.loads(response.read())
                    unread_count = len(data)
                    
                    if unread_count > 0 and not self.has_unread_notification:
                        # Yeni bildirim var
                        msg = random.choice(NOTIFICATION_MESSAGES)
                        # Varsa detaylı bilgi al (ilk bildirim)
                        if data:
                            first = data[0]
                            if 'title' in first:
                                msg = f"{first['title']}: {first.get('message', '...')}"
                        
                        self.tray_icon.showMessage(
                            "KeyCord",
                            msg,
                            QSystemTrayIcon.MessageIcon.NoIcon,
                            3000
                        )
                        self.has_unread_notification = True
                    elif unread_count == 0:
                        self.has_unread_notification = False
                        
        except Exception as e:
            # Hata durumunda (token süresi dolmuş vs) sessiz kal veya logla
            # print(f"Polling error: {e}")
            pass

    def set_api_token(self, token):
        if token:
            self.api_token = token
            # Token alındı, hemen kontrol et
            self.check_notifications()

    def handle_notification_result(self, has_badge):
        # Legacy: Artık API kullanıyoruz ama yedek olarak kalabilir
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

                // Inject QWebChannel source if not present
                if (typeof QWebChannel === 'undefined') {
                    const qwebchannel_js = `
                    /****************************************************************************
                    **
                    ** Copyright (C) 2017 The Qt Company Ltd.
                    ** Contact: https://www.qt.io/licensing/
                    **
                    ** This file is part of the QtWebChannel module of the Qt Toolkit.
                    **
                    ** $QT_BEGIN_LICENSE:BSD$
                    ** Commercial License Usage
                    ** Licensees holding valid commercial Qt licenses may use this file in
                    ** accordance with the commercial license agreement provided with the
                    ** Software or, alternatively, in accordance with the terms contained in
                    ** a written agreement between you and The Qt Company. For licensing terms
                    ** and conditions see https://www.qt.io/terms-conditions. For further
                    ** information use the contact form at https://www.qt.io/contact-us.
                    **
                    ** BSD License Usage
                    ** Alternatively, you may use this file under the terms of the BSD license
                    ** as follows:
                    **
                    ** "Redistribution and use in source and binary forms, with or without
                    ** modification, are permitted provided that the following conditions are
                    ** met:
                    **   * Redistributions of source code must retain the above copyright
                    **     notice, this list of conditions and the following disclaimer.
                    **   * Redistributions in binary form must reproduce the above copyright
                    **     notice, this list of conditions and the following disclaimer in
                    **     the documentation and/or other materials provided with the
                    **     distribution.
                    **   * Neither the name of The Qt Company Ltd nor the names of its
                    **     contributors may be used to endorse or promote products derived
                    **     from this software without specific prior written permission.
                    **
                    **
                    ** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
                    ** "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
                    ** LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
                    ** A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
                    ** OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
                    ** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
                    ** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
                    ** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
                    ** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
                    ** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
                    ** OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
                    **
                    ** $QT_END_LICENSE$
                    **
                    ****************************************************************************/
                    "use strict";var QWebChannelMessageTypes={Init:0,Idle:1,Debug:2,Reply:3,PropertyUpdate:4,Signal:5,ConnectToSignal:6,DisconnectFromSignal:7,SetProperty:8,InstallCallbacks:9,RemoveCallbacks:10,CallMethod:11};var QWebChannel=function(transport,initCallback){if(typeof transport!=="object"||typeof transport.send!=="function"){console.error("The QWebChannel transport object is invalid!");return}var channel=this;this.transport=transport;this.execCallbacks={};this.execId=0;this.exec=function(data,callback){if(typeof callback!=="function"){channel.transport.send(JSON.stringify(data));return}var id=channel.execId++;channel.execCallbacks[id]=callback;data.id=id;channel.transport.send(JSON.stringify(data))};this.objects={};this.debug=function(message){channel.exec({type:QWebChannelMessageTypes.Debug,data:message})};this.transport.onmessage=function(message){var data=JSON.parse(message.data);switch(data.type){case QWebChannelMessageTypes.Reply:var callback=channel.execCallbacks[data.id];if(typeof callback!=="function"){console.error("No callback found for id: "+data.id);return}callback(data.data);delete channel.execCallbacks[data.id];break;case QWebChannelMessageTypes.PropertyUpdate:for(var i in data.data){var propertyUpdate=data.data[i];var object=channel.objects[propertyUpdate.object];if(object){object.__updateProperty__(propertyUpdate.property,propertyUpdate.value)}}break;case QWebChannelMessageTypes.Signal:var object=channel.objects[data.object];if(object){object.__updateSignal__(data.signal,data.args)}break;case QWebChannelMessageTypes.Init:for(var objectName in data.data){var object=new QObject(objectName,data.data[objectName],channel);channel.objects[objectName]=object}channel.exec({type:QWebChannelMessageTypes.Idle});if(initCallback){initCallback(channel)}break;default:console.error("invalid message type: "+data.type);break}};this.exec({type:QWebChannelMessageTypes.Init},function(data){for(var objectName in data){var object=new QObject(objectName,data[objectName],channel);channel.objects[objectName]=object}channel.exec({type:QWebChannelMessageTypes.Idle});if(initCallback){initCallback(channel)}})};var QObject=function(name,data,webChannel){this.__id__=name;this.webChannel=webChannel;this.__properties__={};this.__signals__={};this.__methods__={};this.__callbacks__={};var object=this;for(var i in data.methods){var methodName=data.methods[i][0];this[methodName]=generateMethod(methodName)}for(var i in data.properties){var propertyName=data.properties[i][0];var propertyValue=data.properties[i][1];this[propertyName]=propertyValue;this.__properties__[propertyName]=propertyValue;generateProperty(propertyName)}for(var i in data.signals){var signalName=data.signals[i][0];this[signalName]=new QSignal(name,signalName,webChannel);this.__signals__[signalName]=this[signalName]}this.__updateProperty__=function(propertyName,value){object[propertyName]=value;object.__properties__[propertyName]=value;var signal=object[propertyName+"Changed"];if(signal){signal.__update__(value)}};this.__updateSignal__=function(signalName,args){var signal=object[signalName];if(signal){signal.__update__(args)}};function generateMethod(methodName){return function(){var args=[];var callback;for(var i=0;i<arguments.length;i++){if(typeof arguments[i]==="function")callback=arguments[i];else args.append(arguments[i])}object.webChannel.exec({type:QWebChannelMessageTypes.CallMethod,object:object.__id__,method:methodName,args:args},callback)}}function generateProperty(propertyName){Object.defineProperty(object,propertyName,{get:function(){return object.__properties__[propertyName]},set:function(value){if(value===object.__properties__[propertyName])return;object.webChannel.exec({type:QWebChannelMessageTypes.SetProperty,object:object.__id__,property:propertyName,value:value})},configurable:true,enumerable:true})}};var QSignal=function(objectName,signalName,webChannel){this.objectName=objectName;this.signalName=signalName;this.webChannel=webChannel;this.handlers=[];this.__update__=function(args){for(var i in this.handlers){this.handlers[i].apply(this,args)}};this.connect=function(handler){if(typeof handler!=="function"){console.error("Connect to signal "+signalName+" with non-function handler");return}this.handlers.push(handler);if(this.handlers.length===1){this.webChannel.exec({type:QWebChannelMessageTypes.ConnectToSignal,object:this.objectName,signal:this.signalName})}};this.disconnect=function(handler){var index=this.handlers.indexOf(handler);if(index===-1){console.error("Disconnect from signal "+signalName+" with non-registered handler");return}this.handlers.splice(index,1);if(this.handlers.length===0){this.webChannel.exec({type:QWebChannelMessageTypes.DisconnectFromSignal,object:this.objectName,signal:this.signalName})}}};if(typeof module!=="undefined")module.exports={QWebChannel:QWebChannel,QWebChannelMessageTypes:QWebChannelMessageTypes};
                    `;
                    const s = document.createElement('script');
                    s.innerHTML = qwebchannel_js;
                    document.head.appendChild(s);
                }

                // QWebChannel initialization for native bridge
                if (window.qt && window.qt.webChannelTransport) {
                    new QWebChannel(window.qt.webChannelTransport, function (channel) {
                        window.pybridge = channel.objects.crypto;
                        console.log("KeyCord Native Bridge (X25519) active.");
                    });
                }

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
    app.setOrganizationName("KeyCordOrg")
    app.setApplicationName("KeyCord")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())
