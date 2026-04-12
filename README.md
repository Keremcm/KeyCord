# KeyCord 🔐🌐

KeyCord is a privacy-first, decentralized-inspired messaging platform designed to operate over the **Tor Network**. It combines a unique "Paper/Hand-drawn" aesthetic with state-of-the-art client-side cryptography.

![KeyCord Banner](app/static/logo.png)

## 🌟 Features

### 🛡️ Privacy & Security
- **Zero-Knowledge Architecture:** Your private keys are generated and stored only on your device. The server never sees your plain-text password or private keys.
- **Client-Side Encryption:** All messages are encrypted in the browser using **RSA-OAEP** before being sent.
- **Tor Network Native:** Full support for `.onion` addresses to hide your IP and metadata.
- **No Personal Data:** No phone number or real name required. registration is completely anonymous.

### 💬 Real-time Communication
- **Instant Messaging:** Powered by Socket.IO for real-time delivery.
- **Synchronized Notifications:** Smart notification system that syncs across all open tabs and devices instantly.
- **Groups & Communities:** Create private groups or discover public communities.

### 🎨 Unique Aesthetic
- **Paper Design:** A minimalist "dotted notebook" interface featuring hand-drawn sketches and organic typography.
- **Modern Performance:** Smooth animations (Anime.js) and responsive layout for Mobile & Desktop.

---

## 🛠️ Tech Stack

- **Backend:** Python / Flask
- **Real-time:** Socket.IO
- **Database:** SQLAlchemy (PostgreSQL/SQLite)
- **Encryption:** Forge.js (RSA, AES, SHA-256)
- **Frontend:** Vanilla JS, CSS3, Jinja2
- **Network:** Tor Project / Onion Routing

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Tor Browser (for .onion access)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Keremcm/KeyCord.git
   cd KeyCord
   ```

2. **Setup virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configuration:**
   Create a `.env` file in the root directory:
   ```env
   SECRET_KEY=your_super_secret_key
   DATABASE_URL=sqlite:///keycord.db
   ```

5. **Run the application:**
   ```bash
   python main.py
   ```

---

## 📱 Platforms
KeyCord is designed to be cross-platform. Check the `applications/` directory for:
- 📱 **Android:** Native wrapper (Kotlin)
- 💻 **Windows:** Desktop client (Python/PyQt)
- 🐧 **Linux:** GTK/Qt compatible wrapper

---

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.

## 🤝 Contact
Project Link: [https://github.com/Keremcm/KeyCord](https://github.com/Keremcm/KeyCord)  
Instagram: [@keycord_official](https://www.instagram.com/keycord_official/)

---
*Developed with ❤️ for privacy and freedom.*
