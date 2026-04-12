/**
 * KeyCord Security Mechanism - Anti-Debugging & Code Protection
 * This script implements several techniques to prevent/deter unauthorized code inspection.
 */

(function () {
    'use strict';

    // 1. Block Context Menu (Right Click)
    document.addEventListener('contextmenu', function (e) {
        e.preventDefault();
        return false;
    });

    // 2. Block Keyboard Shortcuts
    document.onkeydown = function (e) {
        // F12
        if (e.keyCode === 123) {
            return false;
        }
        // Ctrl+Shift+I (Inspect)
        if (e.ctrlKey && e.shiftKey && e.keyCode === 73) {
            return false;
        }
        // Ctrl+Shift+J (Console)
        if (e.ctrlKey && e.shiftKey && e.keyCode === 74) {
            return false;
        }
        // Ctrl+Shift+C (Inspect Element)
        if (e.ctrlKey && e.shiftKey && e.keyCode === 67) {
            return false;
        }
        // Ctrl+U (View Source)
        if (e.ctrlKey && e.keyCode === 85) {
            return false;
        }
        // Ctrl+S (Save Page)
        if (e.ctrlKey && e.keyCode === 83) {
            return false;
        }
        // Ctrl+Shift+L (Sometimes used for DevTools or specific extensions)
        if (e.ctrlKey && e.shiftKey && e.keyCode === 76) {
            return false;
        }
    };

    // 3. Debugger Trap (Optimized)
    // Runs less frequently to avoid performance issues
    function startTrap() {
        try {
            (function b(i) {
                if (('' + (i / i)).length !== 1 || i % 20 === 0) {
                    (function () { }).constructor('debugger')();
                } else {
                    debugger;
                }
                if (i < 100) b(++i);
            })(0);
        } catch (e) { }
    }

    // Trigger trap occasionally instead of constantly
    setInterval(startTrap, 5000);

    // 4. Console Detection (Improved)
    function clearPage() {
        // Only clear if body is not already cleared to avoid flicker
        if (document.getElementById('security-alert')) return;

        document.body.innerHTML = `
            <div id="security-alert" style="display:flex;justify-content:center;align-items:center;height:100vh;background:#0f172a;color:#ef4444;font-family:sans-serif;text-align:center;padding:20px;">
                <div>
                    <h1 style="font-size:3rem;margin-bottom:1rem;">Güvenlik Uyarısı</h1>
                    <p style="font-size:1.2rem;">Sistem güvenliği nedeniyle inceleme araçlarının kullanımı kısıtlanmıştır.</p>
                    <button onclick="window.location.reload();" style="margin-top:20px;padding:10px 20px;background:#3b82f6;color:white;border:none;border-radius:5px;cursor:pointer;">Sayfayı Yenile</button>
                    <p style="margin-top:10px; font-size:0.8rem; color:#64748b;">Eğer bu bir hata ise, lütfen tarayıcı pencerenizi tam ekran yapın veya zoom oranını kontrol edin.</p>
                </div>
            </div>`;
    }

    // Detecting if DevTools is open via window size difference (More lenient)
    const threshold = 250; // Increased threshold
    setInterval(function () {
        const widthDiff = window.outerWidth - window.innerWidth;
        const heightDiff = window.outerHeight - window.innerHeight;

        // Check for common DevTools docking positions
        // We also check for devicePixelRatio to account for zoom
        const zoom = window.devicePixelRatio || 1;

        if ((widthDiff > threshold * zoom) || (heightDiff > threshold * zoom)) {
            // Only trigger if a debugger step was also recently hit or timing is suspicious
            // For now, let's just make the threshold larger
            // clearPage(); // Keeping this commented or more lenient to avoid user frustration
            console.warn("DevTools detection: Window size suggests inspection tools might be open.");
        }
    }, 3000);

    // 5. Detection via Timing (Commonly used by anti-debug libraries)
    setInterval(function () {
        const startTime = performance.now();
        debugger;
        const endTime = performance.now();
        if (endTime - startTime > 100) {
            // Debugger was active and paused execution
            clearPage();
        }
    }, 2000);

    // Initial message
    console.log("%cSecurity Active", "color: red; font-size: 20px; font-weight: bold;");
    console.info("DevTools usage is monitored and restricted for security reasons.");

    // Attempt to block console.log output if not in debug mode
    // (In production, this is even more critical)
    /*
    Object.defineProperty(window, 'console', {
        value: window.console,
        writable: false,
        configurable: false
    });
    */

})();
