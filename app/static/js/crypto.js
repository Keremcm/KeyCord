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
    PADDING_SIZE: 4096, // 32768 bits (Fixed packet size)

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
        strToBytes: (str) => Uint8Array.from(str, c => c.charCodeAt(0)),
        bytesToStr: (bytes) => String.fromCharCode(...bytes),
        b64ToBytes: (b64) => Uint8Array.from(window.atob(b64), c => c.charCodeAt(0)),
        bytesToB64: (bytes) => window.btoa(String.fromCharCode(...bytes)),
        padMessage: (text) => {
            const buf = forge.util.createBuffer(text, 'utf8');
            const data = buf.getBytes();
            const len = data.length;
            const maxLen = KEYCORD_CRYPTO.PADDING_SIZE - 2;
            if (len > maxLen) {
                throw new Error("Mesaj çok uzun. Maksimum " + maxLen + " byte.");
            }
            const header = String.fromCharCode((len >> 8) & 0xFF, len & 0xFF);
            const padded = header + data;
            const remaining = KEYCORD_CRYPTO.PADDING_SIZE - padded.length;
            return padded + forge.random.getBytesSync(remaining);
        },
        unpadMessage: (padded) => {
            const len = (padded.charCodeAt(0) << 8) | padded.charCodeAt(1);
            const bytes = padded.substring(2, 2 + len);
            const uint8 = new Uint8Array(bytes.length);
            for (let i = 0; i < bytes.length; i++) {
                uint8[i] = bytes.charCodeAt(i);
            }
            return new TextDecoder('utf-8').decode(uint8);
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
                        const privKeyBytes = Uint8Array.from(atob(myX25519PrivB64), c => c.charCodeAt(0));
                        const pubKeyBytes = Uint8Array.from(atob(recipientPublicKeyBase64), c => c.charCodeAt(0));

                        const sharedSecret = window.X25519.sharedSecret(privKeyBytes, pubKeyBytes);
                        const aesKey = await crypto.subtle.importKey("raw", sharedSecret.slice(0, 32), { name: "AES-GCM" }, false, ["encrypt"]);

                        const nonce = crypto.getRandomValues(new Uint8Array(12));

                        // Padding (Fixed packet size)
                        const encoder = new TextEncoder();
                        const data = encoder.encode(messageText);
                        const msgLen = data.length;
                        const maxLen = KEYCORD_CRYPTO.PADDING_SIZE - 2;
                        if (msgLen > maxLen) {
                            throw new Error("Mesaj çok uzun. Maksimum " + maxLen + " byte.");
                        }
                        const padded = new Uint8Array(KEYCORD_CRYPTO.PADDING_SIZE);
                        padded[0] = (msgLen >> 8) & 0xFF;
                        padded[1] = msgLen & 0xFF;
                        padded.set(data, 2);
                        crypto.getRandomValues(padded.subarray(2 + msgLen));

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
                    const privKeyBytes = Uint8Array.from(atob(myPrivateKeyBase64), c => c.charCodeAt(0));
                    const pubKeyBytes = Uint8Array.from(atob(peerPublicKeyBase64), c => c.charCodeAt(0));

                    const sharedSecret = window.X25519.sharedSecret(privKeyBytes, pubKeyBytes);

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
        if (KEYCORD_CRYPTO.hybrid.available()) {
            return await KEYCORD_CRYPTO.encryptGroupMessageHybrid(messageText, publicKeysMap);
        }
        const aesKey = KEYCORD_CRYPTO.utils.randomBytes(KEYCORD_CRYPTO.AES_KEY_SIZE);
        const iv = KEYCORD_CRYPTO.utils.randomBytes(KEYCORD_CRYPTO.IV_SIZE);
        const cipher = forge.cipher.createCipher('AES-GCM', aesKey);
        cipher.start({ iv: iv });
        cipher.update(forge.util.createBuffer(KEYCORD_CRYPTO.utils.padMessage(messageText)));
        cipher.finish();
        const encryptedKeysMap = {};
        const getRsa = (v) => typeof v === 'string' ? v : ((v && v.public_key) || null);
        for (const [userId, value] of Object.entries(publicKeysMap)) {
            const pubKeyB64 = getRsa(value);
            if (!pubKeyB64) continue;
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
        if (KEYCORD_CRYPTO.isHybridEnvelope(myEncryptedKeyBase64)) {
            return await KEYCORD_CRYPTO.decryptMessageHybrid(encryptedContentBase64, myEncryptedKeyBase64, ivBase64);
        }
        return await KEYCORD_CRYPTO.decryptMessage(encryptedContentBase64, myEncryptedKeyBase64, ivBase64, myPrivateKeyBase64);
    },

    isHybridEnvelope: (value) => {
        if (!value || typeof value !== 'string') return false;
        const t = value.trim();
        return t.startsWith('{') && t.indexOf('"t":"hybrid"') !== -1;
    },

    encryptMessageHybrid: async (messageText, recipientKeys) => {
        const aesKey = crypto.getRandomValues(new Uint8Array(KEYCORD_CRYPTO.AES_KEY_SIZE));
        const iv = crypto.getRandomValues(new Uint8Array(KEYCORD_CRYPTO.IV_SIZE));
        const aesKeyHandle = await crypto.subtle.importKey("raw", aesKey, { name: "AES-GCM" }, false, ["encrypt"]);
        const padded = KEYCORD_CRYPTO.hybrid._pad(new TextEncoder().encode(messageText));
        const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKeyHandle, padded));

        const eph = window.X25519.generateKeyPair();
        const ephPubB64 = KEYCORD_CRYPTO.utils.bytesToB64(eph.publicKey);
        const ephPrivB64 = KEYCORD_CRYPTO.utils.bytesToB64(eph.privateKey);

        const recipEnvelope = await KEYCORD_CRYPTO.hybrid._wrapAesKey(aesKey, recipientKeys, ephPrivB64, ephPubB64);

        const myX = sessionStorage.getItem('kc_x25519_pub');
        const myM = sessionStorage.getItem('kc_mlkem_pub');
        let senderEnvelope = null;
        if (myX && myM) {
            senderEnvelope = await KEYCORD_CRYPTO.hybrid._wrapAesKey(aesKey, { x25519: myX, mlkem: myM }, ephPrivB64, ephPubB64);
        }

        return {
            content: KEYCORD_CRYPTO.utils.bytesToB64(encrypted),
            iv: KEYCORD_CRYPTO.utils.bytesToB64(iv),
            encrypted_aes_key: JSON.stringify(recipEnvelope),
            encrypted_aes_key_sender: senderEnvelope ? JSON.stringify(senderEnvelope) : null,
            key_type: 'HYBRID'
        };
    },

    decryptMessageHybrid: async (encryptedContentBase64, envelopeJson, ivBase64) => {
        const envelope = JSON.parse(envelopeJson);
        const aesKey = await KEYCORD_CRYPTO.hybrid._unwrapAesKey(envelope);
        const aesKeyHandle = await crypto.subtle.importKey("raw", aesKey, { name: "AES-GCM" }, false, ["decrypt"]);
        const encryptedData = KEYCORD_CRYPTO.utils.b64ToBytes(encryptedContentBase64);
        const decryptedPadded = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: KEYCORD_CRYPTO.utils.b64ToBytes(ivBase64) }, aesKeyHandle, encryptedData));
        return KEYCORD_CRYPTO.hybrid._unpad(decryptedPadded);
    },

    encryptGroupMessageHybrid: async (messageText, publicKeysMap) => {
        const aesKey = crypto.getRandomValues(new Uint8Array(KEYCORD_CRYPTO.AES_KEY_SIZE));
        const iv = crypto.getRandomValues(new Uint8Array(KEYCORD_CRYPTO.IV_SIZE));
        const aesKeyHandle = await crypto.subtle.importKey("raw", aesKey, { name: "AES-GCM" }, false, ["encrypt"]);
        const padded = KEYCORD_CRYPTO.hybrid._pad(new TextEncoder().encode(messageText));
        const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKeyHandle, padded));

        const eph = window.X25519.generateKeyPair();
        const ephPubB64 = KEYCORD_CRYPTO.utils.bytesToB64(eph.publicKey);
        const ephPrivB64 = KEYCORD_CRYPTO.utils.bytesToB64(eph.privateKey);

        const encryptedKeysMap = {};
        for (const [userId, value] of Object.entries(publicKeysMap)) {
            try {
                const member = (typeof value === 'string') ? { public_key: value } : (value || {});
                if (member.x25519 && member.mlkem) {
                    const env = await KEYCORD_CRYPTO.hybrid._wrapAesKey(aesKey, { x25519: member.x25519, mlkem: member.mlkem }, ephPrivB64, ephPubB64);
                    encryptedKeysMap[userId] = JSON.stringify(env);
                } else if (member.public_key) {
                    const encryptedKey = KEYCORD_CRYPTO.importPublicKey(member.public_key).encrypt(KEYCORD_CRYPTO.utils.bytesToStr(aesKey), 'RSA-OAEP', { md: forge.md.sha256.create() });
                    encryptedKeysMap[userId] = window.btoa(encryptedKey);
                }
            } catch (e) { console.error(e); }
        }
        return { content: KEYCORD_CRYPTO.utils.bytesToB64(encrypted), iv: KEYCORD_CRYPTO.utils.bytesToB64(iv), encrypted_keys_json: JSON.stringify(encryptedKeysMap), key_type: 'HYBRID' };
    },

    // ═══ Hibrit (X25519 + ML-KEM-768) Post-Quantum Altyapı ═══
    hybrid: {
        available: () => (typeof window !== 'undefined') && window.mlkem_ready === true && typeof window.X25519 !== 'undefined' && typeof crypto !== 'undefined' && !!crypto.subtle,

        _concat: (...arrays) => {
            const total = arrays.reduce((acc, a) => acc + a.length, 0);
            const out = new Uint8Array(total);
            let off = 0;
            for (const a of arrays) { out.set(a, off); off += a.length; }
            return out;
        },

        _pad: (dataBytes) => {
            const msgLen = dataBytes.length;
            const maxLen = KEYCORD_CRYPTO.PADDING_SIZE - 2;
            if (msgLen > maxLen) throw new Error("Mesaj çok uzun. Maksimum " + maxLen + " byte.");
            const padded = new Uint8Array(KEYCORD_CRYPTO.PADDING_SIZE);
            padded[0] = (msgLen >> 8) & 0xFF;
            padded[1] = msgLen & 0xFF;
            padded.set(dataBytes, 2);
            crypto.getRandomValues(padded.subarray(2 + msgLen));
            return padded;
        },

        _unpad: (paddedBytes) => {
            const len = (paddedBytes[0] << 8) | paddedBytes[1];
            const slice = paddedBytes.slice(2, 2 + len);
            return new TextDecoder('utf-8').decode(slice);
        },

        generateX25519KeyPair: async () => {
            const { publicKey, privateKey } = window.X25519.generateKeyPair();
            return {
                x25519Public: KEYCORD_CRYPTO.utils.bytesToB64(publicKey),
                x25519Private: KEYCORD_CRYPTO.utils.bytesToB64(privateKey)
            };
        },

        generateMlkemKeyPair: async () => {
            const { publicKey, privateKey } = await window.mlkem.generateKey("ML-KEM-768", true, ["encapsulateKey", "encapsulateBits", "decapsulateKey", "decapsulateBits"]);
            const pub = new Uint8Array(await window.mlkem.exportKey("raw-public", publicKey));
            const seed = new Uint8Array(await window.mlkem.exportKey("raw-seed", privateKey));
            return {
                mlkemPublic: KEYCORD_CRYPTO.utils.bytesToB64(pub),
                mlkemPrivateSeed: KEYCORD_CRYPTO.utils.bytesToB64(seed)
            };
        },

        generateKeyPair: async () => {
            const x = await KEYCORD_CRYPTO.hybrid.generateX25519KeyPair();
            const m = await KEYCORD_CRYPTO.hybrid.generateMlkemKeyPair();
            return Object.assign({}, x, m, { keyType: 'HYBRID' });
        },

        _deriveWrapKey: async (ikmBytes, saltBytes) => {
            const baseKey = await crypto.subtle.importKey("raw", ikmBytes, "HKDF", false, ["deriveKey"]);
            return await crypto.subtle.deriveKey(
                { name: "HKDF", hash: "SHA-256", salt: saltBytes, info: KEYCORD_CRYPTO.utils.strToBytes("KeyCord-hybrid-v1") },
                baseKey,
                { name: "AES-GCM", length: 256 },
                false,
                ["encrypt", "decrypt"]
            );
        },

        _encapsulate: async (ephemeralPrivB64, recipientX25519B64, recipientMlkemB64) => {
            const x25519Shared = window.X25519.sharedSecret(
                KEYCORD_CRYPTO.utils.b64ToBytes(ephemeralPrivB64),
                KEYCORD_CRYPTO.utils.b64ToBytes(recipientX25519B64)
            );

            const recipMlkemPub = await window.mlkem.importKey("raw-public", KEYCORD_CRYPTO.utils.b64ToBytes(recipientMlkemB64), "ML-KEM-768", true, ["encapsulateKey", "encapsulateBits"]);
            const mlkem = await window.mlkem.encapsulateBits("ML-KEM-768", recipMlkemPub);

            return {
                x25519Shared: x25519Shared,
                mlkemShared: new Uint8Array(mlkem.sharedKey),
                ciphertext: new Uint8Array(mlkem.ciphertext)
            };
        },

        _wrapAesKey: async (aesKeyBytes, recipientKeys, ephemeralPrivB64, ephPubB64) => {
            const shared = await KEYCORD_CRYPTO.hybrid._encapsulate(ephemeralPrivB64, recipientKeys.x25519, recipientKeys.mlkem);
            const ikm = KEYCORD_CRYPTO.hybrid._concat(shared.x25519Shared, shared.mlkemShared);
            const wrapKey = await KEYCORD_CRYPTO.hybrid._deriveWrapKey(ikm, KEYCORD_CRYPTO.utils.b64ToBytes(ephPubB64));
            const wiv = crypto.getRandomValues(new Uint8Array(KEYCORD_CRYPTO.IV_SIZE));
            const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: wiv }, wrapKey, aesKeyBytes));
            return {
                v: 1,
                t: "hybrid",
                epk: ephPubB64,
                ct: KEYCORD_CRYPTO.utils.bytesToB64(shared.ciphertext),
                wiv: KEYCORD_CRYPTO.utils.bytesToB64(wiv),
                c: KEYCORD_CRYPTO.utils.bytesToB64(wrapped)
            };
        },

        _unwrapAesKey: async (envelope) => {
            const ephPubB64 = envelope.epk;
            const myX25519PrivB64 = sessionStorage.getItem('kc_x25519_priv');
            const myMlkemPrivB64 = sessionStorage.getItem('kc_mlkem_priv');
            if (!myX25519PrivB64 || !myMlkemPrivB64) throw new Error("Hibrit özel anahtarlar oturumda yok.");

            const x25519Shared = window.X25519.sharedSecret(
                KEYCORD_CRYPTO.utils.b64ToBytes(myX25519PrivB64),
                KEYCORD_CRYPTO.utils.b64ToBytes(ephPubB64)
            );

            const myMlkemPriv = await window.mlkem.importKey("raw-seed", KEYCORD_CRYPTO.utils.b64ToBytes(myMlkemPrivB64), "ML-KEM-768", true, ["decapsulateKey", "decapsulateBits"]);
            const mlkemShared = new Uint8Array(await window.mlkem.decapsulateBits("ML-KEM-768", myMlkemPriv, KEYCORD_CRYPTO.utils.b64ToBytes(envelope.ct)));

            const ikm = KEYCORD_CRYPTO.hybrid._concat(x25519Shared, mlkemShared);
            const wrapKey = await KEYCORD_CRYPTO.hybrid._deriveWrapKey(ikm, KEYCORD_CRYPTO.utils.b64ToBytes(ephPubB64));
            const wrapped = KEYCORD_CRYPTO.utils.b64ToBytes(envelope.c);
            const aesKey = await crypto.subtle.decrypt({ name: "AES-GCM", iv: KEYCORD_CRYPTO.utils.b64ToBytes(envelope.wiv) }, wrapKey, wrapped);
            return new Uint8Array(aesKey);
        }
    }
};