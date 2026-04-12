/**
 * KEYCORD End-to-End Encryption Library
 * Supports Native X25519 (Windows/Android) and Forge.js RSA Fallback.
 */

const KEYCORD_CRYPTO = {
    // Algoritma sabitleri
    PBKDF2_ITERATIONS: 100000,
    AES_KEY_SIZE: 32, // 256 bits
    IV_SIZE: 12,      // 96 bits for GCM
    TAG_SIZE: 16,     // 128 bits authentication tag
    PADDING_SIZE: 128, // 1024 bits (Fixed packet size)

    // Bridge Detection
    getBridge: () => {
        if (window.pybridge) return { type: 'windows', bridge: window.pybridge };
        if (window.AndroidBridge) return { type: 'android', bridge: window.AndroidBridge };
        return null;
    },

    /**
     * Araçlar: Dönüşüm fonksiyonları
     */
    utils: {
        base64ToBuffer: (b64) => window.atob(b64),
        bufferToBase64: (buf) => window.btoa(buf),
        utf8ToBuffer: (str) => forge.util.createBuffer(str, 'utf8'),
        bufferToUtf8: (buf) => buf.toString('utf8'),
        randomBytes: (length) => forge.random.getBytesSync(length),
        randomSalt: () => window.btoa(forge.random.getBytesSync(16)),
        padMessage: (text) => {
            const buf = forge.util.createBuffer(text, 'utf8');
            const data = buf.getBytes();
            const len = data.length;
            if (len > (KEYCORD_CRYPTO.PADDING_SIZE - 2)) {
                console.warn("Message too long for 1024-bit patch size.");
            }
            const header = String.fromCharCode((len >> 8) & 0xFF, len & 0xFF);
            const padded = header + data;
            const remaining = KEYCORD_CRYPTO.PADDING_SIZE - padded.length;
            if (remaining > 0) return padded + forge.random.getBytesSync(remaining);
            return padded;
        },
        unpadMessage: (padded) => {
            const len = (padded.charCodeAt(0) << 8) | padded.charCodeAt(1);
            return padded.substring(2, 2 + len);
        }
    },

    /**
     * Anahtar Üretimi (Native X25519 veya Forge RSA)
     */
    generateKeyPair: async (username = null) => {
        const native = KEYCORD_CRYPTO.getBridge();
        // Try to get username if not provided
        if (!username) username = localStorage.getItem('kc_username') || 'default_user';

        if (native) {
            console.log(`Using Native Key Generation (${native.type}) for ${username}`);
            return new Promise((resolve) => {
                if (native.type === 'windows') {
                    native.bridge.generate_keys(username, (pubB64) => {
                        resolve({ publicKey: pubB64, keyType: 'X25519' });
                    });
                } else {
                    const pubB64 = native.bridge.generateKeys(username);
                    resolve({ publicKey: pubB64, keyType: 'X25519' });
                }
            });
        }
        return new Promise((resolve, reject) => {
            setTimeout(() => {
                try {
                    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
                    const pubAsn1 = forge.pki.publicKeyToAsn1(keypair.publicKey);
                    const pubB64 = window.btoa(forge.asn1.toDer(pubAsn1).getBytes());
                    const privAsn1 = forge.pki.privateKeyToAsn1(keypair.privateKey);
                    const privDer = forge.asn1.toDer(forge.pki.wrapRsaPrivateKey(privAsn1)).getBytes();
                    const privB64 = window.btoa(privDer);
                    resolve({ publicKey: pubB64, privateKey: privB64, keyType: 'RSA' });
                } catch (err) { reject(err); }
            }, 50);
        });
    },

    deriveKeyFromPassword: (password, saltBase64) => {
        return forge.pkcs5.pbkdf2(password, window.atob(saltBase64), KEYCORD_CRYPTO.PBKDF2_ITERATIONS, KEYCORD_CRYPTO.AES_KEY_SIZE, forge.md.sha256.create());
    },

    encryptPrivateKey: async (privateKeyBase64, password, saltBase64) => {
        const key = KEYCORD_CRYPTO.deriveKeyFromPassword(password, saltBase64);
        const iv = KEYCORD_CRYPTO.utils.randomBytes(KEYCORD_CRYPTO.IV_SIZE);
        const cipher = forge.cipher.createCipher('AES-GCM', key);
        cipher.start({ iv: iv });
        cipher.update(forge.util.createBuffer(window.atob(privateKeyBase64)));
        cipher.finish();
        return window.btoa(iv + cipher.output.getBytes() + cipher.mode.tag.getBytes());
    },

    decryptPrivateKey: async (encryptedPrivateKeyBase64, password, saltBase64) => {
        const key = KEYCORD_CRYPTO.deriveKeyFromPassword(password, saltBase64);
        const combined = window.atob(encryptedPrivateKeyBase64);
        const iv = combined.substring(0, KEYCORD_CRYPTO.IV_SIZE);
        const tag = combined.substring(combined.length - KEYCORD_CRYPTO.TAG_SIZE);
        const encrypted = combined.substring(KEYCORD_CRYPTO.IV_SIZE, combined.length - KEYCORD_CRYPTO.TAG_SIZE);
        const decipher = forge.cipher.createDecipher('AES-GCM', key);
        decipher.start({ iv: iv, tag: forge.util.createBuffer(tag) });
        decipher.update(forge.util.createBuffer(encrypted));
        if (!decipher.finish()) throw new Error("Decryption failed");
        return window.btoa(decipher.output.getBytes());
    },

    importPublicKey: (publicKeyBase64) => forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(window.atob(publicKeyBase64))),
    importPrivateKey: (privateKeyBase64) => forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(window.atob(privateKeyBase64))),

    encryptMessage: async (messageText, recipientPublicKeyBase64, senderPublicKeyBase64, keyType = null, username = null) => {
        const native = KEYCORD_CRYPTO.getBridge();
        if (!username) username = localStorage.getItem('kc_username') || 'default_user';

        // Infer keyType if not provided
        if (!keyType) {
            keyType = (recipientPublicKeyBase64 && recipientPublicKeyBase64.length < 100) ? 'X25519' : 'RSA';
        }

        if (native && keyType === 'X25519') {
            return new Promise((resolve, reject) => {
                const handle = (res) => {
                    const data = JSON.parse(res);
                    if (data.error) reject(data.error);
                    else resolve({
                        content: data.ciphertext,
                        iv: data.nonce,
                        encrypted_aes_key: senderPublicKeyBase64, // Per recipient
                        encrypted_aes_key_sender: recipientPublicKeyBase64, // Per sender
                        key_type: 'X25519'
                    });
                };
                if (native.type === 'windows') native.bridge.encrypt(messageText, recipientPublicKeyBase64, username, handle);
                else handle(native.bridge.encrypt(messageText, recipientPublicKeyBase64, username));
            });
        }

        // Web Fallback for X25519 Encryption
        if (keyType === 'X25519' && window.crypto && crypto.subtle) {
            try {
                const myX25519PrivB64 = localStorage.getItem('kc_x25519_priv');
                if (myX25519PrivB64 && recipientPublicKeyBase64) {
                    const encryptX25519 = async () => {
                        const privKeyBuf = Uint8Array.from(atob(myX25519PrivB64), c => c.charCodeAt(0)).buffer;
                        const pubKeyBuf = Uint8Array.from(atob(recipientPublicKeyBase64), c => c.charCodeAt(0)).buffer;

                        const importedPriv = await crypto.subtle.importKey("raw", privKeyBuf, { name: "X25519" }, false, ["deriveBits"]);
                        const importedPub = await crypto.subtle.importKey("raw", pubKeyBuf, { name: "X25519" }, false, []);

                        const sharedSecret = await crypto.subtle.deriveBits({ name: "X25519", public: importedPub }, importedPriv, 256);
                        const aesKey = await crypto.subtle.importKey("raw", sharedSecret.slice(0, 32), { name: "AES-GCM" }, false, ["encrypt"]);

                        const nonce = crypto.getRandomValues(new Uint8Array(12));

                        // Padding (128 bytes)
                        const encoder = new TextEncoder();
                        const data = encoder.encode(messageText);
                        const msgLen = data.length;
                        const padded = new Uint8Array(128);
                        padded[0] = (msgLen >> 8) & 0xFF;
                        padded[1] = msgLen & 0xFF;
                        padded.set(data, 2);
                        if (msgLen < 126) {
                            crypto.getRandomValues(padded.subarray(2 + msgLen));
                        }

                        const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, padded);
                        return {
                            content: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
                            iv: btoa(String.fromCharCode(...nonce)),
                            encrypted_aes_key: senderPublicKeyBase64, // Per recipient
                            encrypted_aes_key_sender: recipientPublicKeyBase64, // Per sender
                            key_type: 'X25519'
                        };
                    };
                    return await encryptX25519();
                }
            } catch (e) {
                console.error("JS X25519 Encryption Fallback failed", e);
            }
        }

        const aesKey = KEYCORD_CRYPTO.utils.randomBytes(KEYCORD_CRYPTO.AES_KEY_SIZE);
        const iv = KEYCORD_CRYPTO.utils.randomBytes(KEYCORD_CRYPTO.IV_SIZE);
        const cipher = forge.cipher.createCipher('AES-GCM', aesKey);
        cipher.start({ iv: iv });
        cipher.update(forge.util.createBuffer(KEYCORD_CRYPTO.utils.padMessage(messageText)));
        cipher.finish();
        const encryptedAesKey = KEYCORD_CRYPTO.importPublicKey(recipientPublicKeyBase64).encrypt(aesKey, 'RSA-OAEP', { md: forge.md.sha256.create() });
        let encryptedAesKeySender = null;
        if (senderPublicKeyBase64 && senderPublicKeyBase64 !== 'None') {
            try {
                encryptedAesKeySender = window.btoa(KEYCORD_CRYPTO.importPublicKey(senderPublicKeyBase64).encrypt(aesKey, 'RSA-OAEP', { md: forge.md.sha256.create() }));
            } catch (e) { console.warn("Sender key encryption failed:", e); }
        }
        return { content: window.btoa(cipher.output.getBytes() + cipher.mode.tag.getBytes()), iv: window.btoa(iv), encrypted_aes_key: window.btoa(encryptedAesKey), encrypted_aes_key_sender: encryptedAesKeySender, key_type: 'RSA' };
    },

    decryptMessage: async (encryptedContentBase64, encryptedAesKeyBase64, ivBase64, myPrivateKeyBase64, keyType = null, senderPublicKeyBase64 = null, username = null) => {
        const native = KEYCORD_CRYPTO.getBridge();
        if (!username) username = localStorage.getItem('kc_username') || 'default_user';

        // Use encryptedAesKeyBase64 as peerPublicKey if senderPublicKeyBase64 is null (Common in UI calls)
        const peerPublicKeyBase64 = senderPublicKeyBase64 || encryptedAesKeyBase64;

        // Infer keyType if not provided
        if (!keyType) {
            keyType = (peerPublicKeyBase64 && peerPublicKeyBase64.length < 100) ? 'X25519' : 'RSA';
        }

        if (native && keyType === 'X25519') {
            return new Promise((resolve) => {
                if (native.type === 'windows') native.bridge.decrypt(encryptedContentBase64, ivBase64, peerPublicKeyBase64, username, resolve);
                else resolve(native.bridge.decrypt(encryptedContentBase64, ivBase64, peerPublicKeyBase64, username));
            });
        }

        // Web Fallback for X25519 Decryption
        if (keyType === 'X25519' && window.crypto && crypto.subtle && myPrivateKeyBase64) {
            try {
                // This requires myPrivateKeyBase64 to be an X25519 private key (raw bytes base64)
                // and senderPublicKeyBase64 to be an X25519 public key.
                const decryptX25519 = async () => {
                    const privKeyBuf = Uint8Array.from(atob(myPrivateKeyBase64), c => c.charCodeAt(0)).buffer;
                    const pubKeyBuf = Uint8Array.from(atob(peerPublicKeyBase64), c => c.charCodeAt(0)).buffer;

                    const importedPriv = await crypto.subtle.importKey("raw", privKeyBuf, { name: "X25519" }, false, ["deriveBits"]);
                    const importedPub = await crypto.subtle.importKey("raw", pubKeyBuf, { name: "X25519" }, false, []);

                    const sharedSecret = await crypto.subtle.deriveBits({ name: "X25519", public: importedPub }, importedPriv, 256);

                    // HKDF-like derivation (simplified to match native's Simple derivation if native doesn't use HKDF)
                    // Native (Android) currently uses first 32 bytes of shared secret.
                    const aesKey = await crypto.subtle.importKey("raw", sharedSecret.slice(0, 32), { name: "AES-GCM" }, false, ["decrypt"]);

                    const encryptedData = Uint8Array.from(atob(encryptedContentBase64), c => c.charCodeAt(0));
                    const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));

                    const decryptedPadded = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, aesKey, encryptedData);
                    const decryptedArray = new Uint8Array(decryptedPadded);

                    // Unpadding
                    const msgLen = (decryptedArray[0] << 8) | decryptedArray[1];
                    return new TextDecoder().decode(decryptedArray.slice(2, 2 + msgLen));
                };
                return await decryptX25519();
            } catch (e) {
                console.error("JS X25519 Decryption failed. Falling back to RSA or error.", e);
            }
        }
        const aesKey = KEYCORD_CRYPTO.importPrivateKey(myPrivateKeyBase64).decrypt(window.atob(encryptedAesKeyBase64), 'RSA-OAEP', { md: forge.md.sha256.create() });
        const combined = window.atob(encryptedContentBase64);
        const tag = combined.substring(combined.length - KEYCORD_CRYPTO.TAG_SIZE);
        const ciphertext = combined.substring(0, combined.length - KEYCORD_CRYPTO.TAG_SIZE);
        const decipher = forge.cipher.createDecipher('AES-GCM', aesKey);
        decipher.start({ iv: window.atob(ivBase64), tag: forge.util.createBuffer(tag) });
        decipher.update(forge.util.createBuffer(ciphertext));
        if (!decipher.finish()) throw new Error("Decryption failed");
        return KEYCORD_CRYPTO.utils.unpadMessage(decipher.output.getBytes());
    },

    encryptGroupMessage: async (messageText, publicKeysMap) => {
        const aesKey = KEYCORD_CRYPTO.utils.randomBytes(KEYCORD_CRYPTO.AES_KEY_SIZE);
        const iv = KEYCORD_CRYPTO.utils.randomBytes(KEYCORD_CRYPTO.IV_SIZE);
        const cipher = forge.cipher.createCipher('AES-GCM', aesKey);
        cipher.start({ iv: iv });
        cipher.update(forge.util.createBuffer(KEYCORD_CRYPTO.utils.padMessage(messageText)));
        cipher.finish();
        const encryptedKeysMap = {};
        for (const [userId, pubKeyB64] of Object.entries(publicKeysMap)) {
            try {
                const encryptedKey = KEYCORD_CRYPTO.importPublicKey(pubKeyB64).encrypt(aesKey, 'RSA-OAEP', { md: forge.md.sha256.create() });
                encryptedKeysMap[userId] = window.btoa(encryptedKey);
            } catch (e) { console.error(e); }
        }
        return { content: window.btoa(cipher.output.getBytes() + cipher.mode.tag.getBytes()), iv: window.btoa(iv), encrypted_keys_json: JSON.stringify(encryptedKeysMap) };
    },

    decryptGroupMessage: async (encryptedContentBase64, encryptedKeysJson, ivBase64, myUserId, myPrivateKeyBase64) => {
        const keysMap = JSON.parse(encryptedKeysJson);
        const myEncryptedKeyBase64 = keysMap[String(myUserId)];
        if (!myEncryptedKeyBase64) throw new Error("No key found");
        return await KEYCORD_CRYPTO.decryptMessage(encryptedContentBase64, myEncryptedKeyBase64, ivBase64, myPrivateKeyBase64);
    }
};