/**
 * PROJECT STRATOSPHERE ENGINE
 * 
 * Components:
 * 1. VirtualScroll: Handles inertia scrolling
 * 2. Renderer: Manages Canvas Contexts and Loop
 * 3. JitterBox: Procedural messy border renderer
 * 4. ParticleSystem: The Digital Onion
 * 5. TextScrambler: Matrix-like text reveal
 */

class VirtualScroll {
    constructor() {
        this.container = document.getElementById('scroll-container');
        // No transform needed - using native scroll
        this.y = 0;
        this.targetY = 0;
        this.maxScroll = 0;
        this.speed = 0.1; // Inertia factor (lower = smoother/slower)

        this.resize();
        window.addEventListener('resize', () => this.resize());
        window.addEventListener('wheel', (e) => this.onWheel(e), { passive: false });

        // Touch support simplified
        this.touchStart = 0;
        window.addEventListener('touchstart', e => this.touchStart = e.touches[0].clientY);
        window.addEventListener('touchmove', e => {
            const dy = this.touchStart - e.touches[0].clientY;
            this.targetY += dy * 2;
            this.touchStart = e.touches[0].clientY;
        });

        // Keyboard support
        window.addEventListener('keydown', (e) => this.onKey(e));
    }

    resize() {
        this.maxScroll = this.container.scrollHeight - window.innerHeight;
    }

    onWheel(e) {
        e.preventDefault();
        this.targetY += e.deltaY * 0.5;
        this.targetY = Math.max(0, Math.min(this.targetY, this.maxScroll));
    }

    onKey(e) {
        const step = 100;
        if (e.key === 'ArrowDown') this.targetY += step;
        if (e.key === 'ArrowUp') this.targetY -= step;
        if (e.key === 'PageDown') this.targetY += window.innerHeight;
        if (e.key === 'PageUp') this.targetY -= window.innerHeight;
        if (e.key === 'Home') this.targetY = 0;
        if (e.key === 'End') this.targetY = this.maxScroll;
        this.targetY = Math.max(0, Math.min(this.targetY, this.maxScroll));
    }
}

// === KEYCORD NATIVE SCROLL ENGINE ===
// Simplified: No custom scroll physics, just native browser scrolling.
// Background animations (Particles, Jitter) are driven by window.scrollY.

// Text Scrambler (Deciphering Effect)
class TextScrambler {
    constructor() {
        // Updated with Turkish chars and tech symbols
        this.chars = '!<>-_\\/[]{}—=+*^?#________İıŞşĞğÇçÖöÜü';
        this.queue = [];
        this.frame = 0;

        // Find all scramblers
        document.querySelectorAll('.scrambler').forEach(el => {
            this.queue.push({
                el: el,
                originalText: el.innerText,
                currentText: '',
                progress: 0,
                scrambleDuration: 60, // frames
                active: false
            });
            el.innerText = ''; // Clear initially
        });
    }

    trigger(element) {
        const item = this.queue.find(i => i.el === element);
        if (item && !item.active) {
            item.active = true;
            item.progress = 0;
        }
    }

    update() {
        this.frame++;
        this.queue.forEach(item => {
            if (!item.active) return;

            if (item.progress < item.originalText.length) {
                if (this.frame % 3 === 0) { // Speed control
                    item.progress += 0.5; // slow reveal
                    let out = '';
                    for (let i = 0; i < item.originalText.length; i++) {
                        if (i < Math.floor(item.progress)) {
                            out += item.originalText[i];
                        } else {
                            out += this.chars[Math.floor(Math.random() * this.chars.length)];
                        }
                    }
                    item.el.innerText = out;
                }
            } else {
                // Done, clear random chars
                if (item.el.innerText !== item.originalText) {
                    item.el.innerText = item.originalText;
                }
            }
        });
    }
}

class JitterRenderer {
    constructor(ctx, scrollY) {
        this.ctx = ctx;
        this.scrollY = scrollY; // Ref to scroll
    }

    drawBox(el, scrollY, color = '#fff') {
        const rect = el.getBoundingClientRect();

        // If offscreen, skip
        if (rect.bottom < 0 || rect.top > window.innerHeight) return;

        // Jitter params
        const j = 1.5; // Jitter amount

        this.ctx.beginPath();
        this.ctx.strokeStyle = color;
        this.ctx.lineWidth = 2;

        // Draw 2 passes for "sketchy" look
        for (let i = 0; i < 2; i++) {
            const x = rect.left;
            const y = rect.top;
            const w = rect.width;
            const h = rect.height;

            this.ctx.moveTo(x + Math.random() * j, y + Math.random() * j);
            this.ctx.lineTo(x + w + Math.random() * j, y + Math.random() * j);
            this.ctx.lineTo(x + w + Math.random() * j, y + h + Math.random() * j);
            this.ctx.lineTo(x + Math.random() * j, y + h + Math.random() * j);
            this.ctx.lineTo(x + Math.random() * j, y + Math.random() * j);
        }
        this.ctx.stroke();
    }
}

class ParticleSystem {
    constructor(ctx, width, height) {
        this.ctx = ctx;
        this.width = width;
        this.height = height;
        this.particles = [];
        this.initOnion();
    }

    initOnion() {
        // Create sphere points
        const count = 400;
        for (let i = 0; i < count; i++) {
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos((Math.random() * 2) - 1);
            const r = 150; // Radius

            this.particles.push({
                x: 0, y: 0, z: 0, // Projected
                ox: r * Math.sin(phi) * Math.cos(theta), // Original 3D
                oy: r * Math.sin(phi) * Math.sin(theta),
                oz: r * Math.cos(phi),
                char: Math.random() > 0.5 ? '0' : '1',
                active: true
            });
        }
    }

    updateAndDraw(scrollY, mouseX, mouseY) {
        const centerX = this.width / 2;
        const centerY = this.height / 2;

        // Scroll Effect: Explode onion
        // Map scrollY to explosion factor
        const explosion = Math.min(scrollY * 2, 2000); // 0 to 2000

        this.ctx.fillStyle = '#aaaaaa';
        this.ctx.font = '12px monospace';
        this.ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
        this.ctx.lineWidth = 1;

        // Rotate based on mouse
        const rotX = (mouseY - centerY) * 0.002;
        const rotY = (mouseX - centerX) * 0.002;

        // Pre-calculate positions
        const projected = [];

        this.particles.forEach(p => {
            // 3D Rotation
            let x = p.ox;
            let y = p.oy;
            let z = p.oz;

            // Rotation Logic (Simplified Matrix mult)
            // Rotate Y
            let x1 = x * Math.cos(rotY) - z * Math.sin(rotY);
            let z1 = z * Math.cos(rotY) + x * Math.sin(rotY);
            // Rotate X
            let y1 = y * Math.cos(rotX) - z1 * Math.sin(rotX);
            let z2 = z1 * Math.cos(rotX) + y * Math.sin(rotX);

            // Explosion Logic
            const expFactor = 1 + (scrollY * 0.005);
            x1 *= expFactor;
            y1 *= expFactor;
            z2 *= expFactor;

            // Projection
            const scale = 300 / (300 + z2);
            const projX = x1 * scale + centerX;
            const projY = y1 * scale + centerY;

            // Store for line drawing
            if (scale > 0) {
                projected.push({ x: projX, y: projY, z: z2, char: p.char, scale: scale });
            }
        });

        // Draw Lines (Constellation Effect) - "Decoration"
        // Only draw between close particles to create a network look
        // Performance Note: O(N^2) is bad, but N=400 is fine (~160k checks, manageable in JS)
        // Optimization: Check dist squared
        this.ctx.beginPath();
        for (let i = 0; i < projected.length; i++) {
            const p1 = projected[i];

            // Draw particle
            this.ctx.globalAlpha = Math.min(1, p1.scale * 0.5);
            this.ctx.fillText(p1.char, p1.x, p1.y);

            // Connect lines?
            // Limit connections to avoid clutter. 
            // Only connect if scrollY is low (sphere is intact) OR high (explosion network)
            // Let's keep it subtle
            for (let j = i + 1; j < projected.length; j++) {
                const p2 = projected[j];
                const dx = p1.x - p2.x;
                const dy = p1.y - p2.y;
                const distSq = dx * dx + dy * dy;

                // Connection distance threshold. Increases as they explode to keep connections?
                // No, fixed threshold creates "breaking links" effect which is cool
                if (distSq < 2000) { // roughly 45px
                    this.ctx.moveTo(p1.x, p1.y);
                    this.ctx.lineTo(p2.x, p2.y);
                }
            }
        }
        this.ctx.stroke();
        this.ctx.globalAlpha = 1;
    }
}

class MatrixRain {
    constructor(ctx, width, height) {
        this.ctx = ctx;
        this.width = width;
        this.height = height;
        this.cols = Math.floor(width / 20);
        this.drops = [];
        this.init();
    }

    init() {
        this.drops = [];
        for (let i = 0; i < this.cols; i++) {
            this.drops[i] = Math.random() * -100; // Start above screen
        }
    }

    updateAndDraw(scrollY) {
        this.ctx.fillStyle = '#0f0'; // Base color (greenish)
        this.ctx.font = '15px monospace';

        // Scroll influences speed
        const speed = 1 + (scrollY * 0.005);

        for (let i = 0; i < this.drops.length; i++) {
            // Random char
            const char = String.fromCharCode(0x30A0 + Math.random() * 96);

            // Color based on scroll depth?
            // Let's make it white/grey to fit theme
            const alpha = Math.random();
            this.ctx.fillStyle = `rgba(200, 200, 200, ${alpha})`;

            this.ctx.fillText(char, i * 20, this.drops[i]);

            // Move down
            this.drops[i] += speed * Math.random();

            // Reset if bottom
            if (this.drops[i] > this.height && Math.random() > 0.975) {
                this.drops[i] = 0;
            }
        }
    }
}

class EncryptionField {
    // Designed for the whitepaper background: A field of static noise that "decrypts" into structure based on scroll
    constructor(ctx, width, height) {
        this.ctx = ctx;
        this.width = width;
        this.height = height;
        this.rows = Math.floor(height / 20);
        this.cols = Math.floor(width / 20);
    }

    updateAndDraw(scrollY) {
        this.ctx.font = '14px monospace';
        const scrollFactor = scrollY * 0.002; // How much "order" we have

        for (let y = 0; y < this.rows; y++) {
            for (let x = 0; x < this.cols; x++) {
                // Determine chaos level for this cell
                // Higher scroll = less chaos
                // We create a "wave" of decryption moving down

                const myY = y * 20;
                const distFromScroll = Math.abs(myY - (scrollY % this.height)); // Decryption wave follows scroll

                // If close to the "wave", we show bright, stable chars
                // If far, we show dim, random noise

                if (distFromScroll < 200) {
                    // Active "Decryption" Zone
                    this.ctx.fillStyle = '#fff';
                    this.ctx.fillText(String.fromCharCode(0x30A0 + Math.random() * 32), x * 20, y * 20);
                } else if (Math.random() > 0.98) {
                    // Background noise
                    this.ctx.fillStyle = 'rgba(100,100,100,0.2)';
                    this.ctx.fillText((Math.random() > 0.5 ? '0' : '1'), x * 20, y * 20);
                }
            }
        }
    }
}

/** -- MAIN INIT -- */
document.addEventListener('DOMContentLoaded', () => {

    // Setup Canvas
    const canvasUI = document.getElementById('canvas-ui');
    const ctxUI = canvasUI.getContext('2d');
    const canvasMain = document.getElementById('canvas-main');
    const ctxMain = canvasMain.getContext('2d');

    let width = window.innerWidth;
    let height = window.innerHeight;

    const resize = () => {
        width = window.innerWidth;
        height = window.innerHeight;
        canvasUI.width = width;
        canvasUI.height = height;
        canvasMain.width = width;
        canvasMain.height = height;
    };
    window.addEventListener('resize', resize);
    resize();

    // === NATIVE SCROLL SETUP ===
    document.body.style.overflow = 'auto';
    document.body.style.height = 'auto';
    const scrollContainer = document.getElementById('scroll-container');
    if (scrollContainer) {
        scrollContainer.style.position = 'relative';
        scrollContainer.style.transform = 'none';
    }

    // Systems
    const scrim = new TextScrambler();
    const jitter = new JitterRenderer(ctxUI);
    const particles = new ParticleSystem(ctxMain, width, height);

    // Mouse Tracking
    let mouse = { x: width / 2, y: height / 2 };
    window.addEventListener('mousemove', e => {
        mouse.x = e.clientX;
        mouse.y = e.clientY;

        // Update Spotlight
        const spot = document.getElementById('cursor-spotlight');
        if (spot) spot.style.transform = `translate(${e.clientX}px, ${e.clientY}px) translate(-50%, -50%)`;
    });

    // Loading Simulation
    const loader = document.getElementById('loader');
    const bar = document.querySelector('.bar-fill');
    let loadProgress = 0;

    // Simulate asset load
    const interval = setInterval(() => {
        loadProgress += Math.random() * 10;
        if (loadProgress >= 100) {
            loadProgress = 100;
            clearInterval(interval);
            setTimeout(() => {
                document.body.classList.add('loaded');
                // Trigger initial scrambles
                scrim.trigger(document.querySelector('.mega-title'));
            }, 500);
        }
        if (bar) bar.style.width = `${loadProgress}%`;
    }, 50);

    // Loop
    function loop() {
        const scrollY = window.scrollY;

        // Clear Canvases
        ctxUI.clearRect(0, 0, width, height);
        ctxMain.clearRect(0, 0, width, height);

        // Update Systems
        particles.width = width; particles.height = height; // Ensure center
        particles.updateAndDraw(scrollY, mouse.x, mouse.y);

        // Removed Page Detection -> Always use the Sphere (it's what the user prefers now)
        // Previous Matrix effect was considered "too complex"

        scrim.update();

        // Draw Jitter Borders
        // We find all elements with .jitter-box or .jitter-border class
        const boxes = document.querySelectorAll('.jitter-box, .jitter-border');
        boxes.forEach(box => {
            jitter.drawBox(box, scrollY, '#ffffff');
        });

        // Trigger scramblers if they come into view
        const headers = document.querySelectorAll('.scrambler');
        headers.forEach(h => {
            const rect = h.getBoundingClientRect();
            if (rect.top < height && rect.bottom > 0) {
                scrim.trigger(h);
            }
        });

        requestAnimationFrame(loop);
    }
    loop();

    // Copy Logic
    const terminal = document.querySelector('.onion-terminal');
    if (terminal) {
        terminal.addEventListener('click', () => {
            navigator.clipboard.writeText(document.getElementById('onion-text').innerText);
            terminal.classList.add('copied');
            setTimeout(() => terminal.classList.remove('copied'), 2000);
        });
    }
})
