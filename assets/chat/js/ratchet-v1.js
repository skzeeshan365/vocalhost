"use strict";

async function importKey(key, usage) {
    return await crypto.subtle.importKey(
        'raw',
        key,
        {name: 'HKDF'},
        false,
        usage
    )
}

async function exportKey(format, publicKey) {
    return await crypto.subtle.exportKey(format, publicKey);
}

async function deriveKey(privateKey, publicKey) {
    return await crypto.subtle.deriveKey(
        {name: 'ECDH', public: publicKey},
        privateKey,
        {name: 'AES-GCM', length: 256},
        true,
        ['encrypt', 'decrypt']
    );
}

async function encryptMessage(key, iv, message) {
    const encodedMessage = new TextEncoder().encode(message);

    // Ensure that the key usage is set to 'encrypt'
    const derivedKey = await importKey(key, ['deriveKey'])

    const aesKey = await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(0), // You might want to use a proper salt
            info: new TextEncoder().encode('AES key derivation'),
        },
        derivedKey,
        {name: 'AES-GCM', length: 256},
        true,
        ['encrypt', 'decrypt']
    );

    const encrypted = await crypto.subtle.encrypt(
        {name: 'AES-GCM', iv},
        aesKey,
        encodedMessage
    );

    return new Uint8Array(encrypted);
}

async function decryptMessage(key, iv, encryptedMessage) {
    const derivedKey = await importKey(key, ['deriveKey'])

    const aesKey = await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(0), // You might want to use a proper salt
            info: new TextEncoder().encode('AES key derivation'),
        },
        derivedKey,
        {name: 'AES-GCM', length: 256},
        true,
        ['encrypt', 'decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
        {name: 'AES-GCM', iv},
        aesKey,
        encryptedMessage
    );

    return new TextDecoder().decode(decrypted);
}

async function encryptImage(key, iv, imageBlob) {
    const imageArrayBuffer = await imageBlob.arrayBuffer();

    const derivedKey = await importKey(key, ['deriveKey']);

    const aesKey = await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(0),
            info: new TextEncoder().encode('AES key derivation'),
        },
        derivedKey,
        {name: 'AES-GCM', length: 256},
        true,
        ['encrypt', 'decrypt']
    );

    const encryptedImage = await crypto.subtle.encrypt(
        {name: 'AES-GCM', iv},
        aesKey,
        imageArrayBuffer
    );

    return new Uint8Array(encryptedImage);
}

async function decryptImage(key, iv, encryptedImage) {
    const derivedKey = await importKey(key, ['deriveKey']);

    const aesKey = await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(0), // You might want to use a proper salt
            info: new TextEncoder().encode('AES key derivation'),
        },
        derivedKey,
        {name: 'AES-GCM', length: 256},
        true,
        ['encrypt', 'decrypt']
    );

    const decryptedImage = await crypto.subtle.decrypt(
        {name: 'AES-GCM', iv},
        aesKey,
        encryptedImage
    );

    return new Uint8Array(decryptedImage);

}

async function hkdf(input, length) {
    const hkdfKey = await importKey(input, ['deriveBits'])

    return crypto.subtle.deriveBits(
        {name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new Uint8Array(0)},
        hkdfKey,
        length * 8
    );
}


function b64(msg) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(msg)));
}


class SymmRatchet {
    constructor(key) {
        this.state = key;
    }

    logInitialState() {
        console.log('State:', b64(this.state));
    }

    async next(inp) {
        if (inp) {
            inp = await crypto.subtle.exportKey('raw', inp);
        }
        const stateArray = new Uint8Array(this.state);
        const inputArray = new Uint8Array(inp);

        let derivedBits = await hkdf(new Uint8Array([...stateArray, ...inputArray]), 80);

        const derivedArray = new Uint8Array(derivedBits);
        this.state = derivedArray.slice(0, 32)
        const outKey = derivedArray.slice(32, 64);
        const iv = derivedArray.slice(64, 80);

        return [outKey, iv];
    }
}

class Bob {
    constructor(room, device_id, asymm) {
        this.IKb = {};
        this.SPKb = {};
        this.OPKb = {};
        this.DHratchet = {};
        this.receiver_public_key = null;
        this.room = room;
        this.device_id = device_id;
        this.version = null;
        this.asymm = asymm;
    }

    async setReceiverKey(key) {
        let public_key = base64StringToArrayBuffer(key);
        this.receiver_public_key = await crypto.subtle.importKey(
            'spki',
            public_key,
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            []
        );
    }

    async setReceiverKey_JWK(key) {
        const base64DecodedPublicKey = atob(key);
        const receivedJWK = JSON.parse(base64DecodedPublicKey);
        this.receiver_public_key = await crypto.subtle.importKey(
            'jwk',
            receivedJWK,
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            []
        );
    }

    async setReceiverKey_RAW(key) {
        this.receiver_public_key = await crypto.subtle.importKey(
            'raw',
            key,
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            []
        );
    }

    async x3dh(keys) {
        let ikkey = base64StringToArrayBuffer(keys[0]);
        let ekkey = base64StringToArrayBuffer(keys[1]);
        let IKa = await crypto.subtle.importKey(
            'spki',
            ikkey,
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            []
        );

        let EKa = await crypto.subtle.importKey(
            'spki',
            ekkey,
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            []
        );

        const dh1 = await deriveKey(this.SPKb.privateKey, IKa);
        const dh2 = await deriveKey(this.IKb.privateKey, EKa);
        const dh3 = await deriveKey(this.SPKb.privateKey, EKa);
        const dh4 = await deriveKey(this.OPKb.privateKey, EKa);

        const dh1Bits = new Uint8Array(await exportKey('raw', dh1));
        const dh2Bits = new Uint8Array(await exportKey('raw', dh2));
        const dh3Bits = new Uint8Array(await exportKey('raw', dh3));
        const dh4Bits = new Uint8Array(await exportKey('raw', dh4));

        this.sk = await hkdf(new Uint8Array([...dh1Bits, ...dh2Bits, ...dh3Bits, ...dh4Bits]), 32);
        console.log('[Bob]\tShared key:', b64(this.sk));
        await this.loadDhRatchetKey();
    }

    async loadDhRatchetKey() {
        let dhRatchetPrivateKey = await this.asymm.decryptKeys(getDHRatchetKey(this.room));
        this.DHratchet.privateKey = await crypto.subtle.importKey(
            'pkcs8',
            dhRatchetPrivateKey,
            {name: 'ECDH', namedCurve: 'P-256'},
            false,
            ['deriveKey']
        );
    }

    async retrieveAndImportKeys() {
        let roomData = getKeysByRoom(this.room);

        this.version = roomData.version;

        if (roomData && roomData.private_keys) {
            let ikPrivateKey = await this.asymm.decryptKeys(roomData.private_keys.ikPrivateKey);
            let spkPrivateKey = await this.asymm.decryptKeys(roomData.private_keys.spkPrivateKey);
            let opkPrivateKey = await this.asymm.decryptKeys(roomData.private_keys.opkPrivateKey);

            this.IKb.privateKey = await crypto.subtle.importKey(
                'pkcs8',
                ikPrivateKey,
                {name: 'ECDH', namedCurve: 'P-256'},
                false,
                ['deriveKey']
            );
            this.SPKb.privateKey = await crypto.subtle.importKey(
                'pkcs8',
                spkPrivateKey,
                {name: 'ECDH', namedCurve: 'P-256'},
                false,
                ['deriveKey']
            );

            this.OPKb.privateKey = await crypto.subtle.importKey(
                'pkcs8',
                opkPrivateKey,
                {name: 'ECDH', namedCurve: 'P-256'},
                false,
                ['deriveKey']
            );
        }
    }

    async saveToLocalStorage() {
        let root = b64(await this.asymm.encryptKeys(new Uint8Array(this.rootRatchet.state)));
        let recv = b64(await this.asymm.encryptKeys(new Uint8Array(this.recvRatchet.state)));
        let send = b64(await this.asymm.encryptKeys(new Uint8Array(this.sendRatchet.state)));
        saveRatchetState(this.room, this.device_id, b64(this.sk), root, recv, send);
    }

    async initRatchets() {
        let currentSk = b64(this.sk);
        let previousSk = getSk(this.room, this.device_id, b64(this.sk));
        if (currentSk === previousSk) {
            let states = getRatchetState(this.room, this.device_id, b64(this.sk));

            if (states) {
                this.rootRatchet = new SymmRatchet(await this.asymm.decryptKeys(states.rootRatchetState));
                this.recvRatchet = new SymmRatchet(await this.asymm.decryptKeys(states.recvRatchetState));
                this.sendRatchet = new SymmRatchet(await this.asymm.decryptKeys(states.sendRatchetState));
            } else {
                this.rootRatchet = new SymmRatchet(this.sk);
                this.sendRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
                this.recvRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
            }
        } else {
            this.rootRatchet = new SymmRatchet(this.sk);
            this.sendRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
            this.recvRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
            saveSk(this.room, b64(this.sk), this.device_id);
            deleteRatchetStates(this.room, this.device_id, b64(this.sk));
        }
    }

    async send_dhRatchet(alicePublic) {
        this.DHratchet = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );

        saveDHRatchetKey(b64(await this.asymm.encryptKeys(await exportKey('pkcs8', this.DHratchet.privateKey))), this.room);

        const dhSend = await deriveKey(this.DHratchet.privateKey, alicePublic);
        const sharedSend = (await this.rootRatchet.next(dhSend))[0];
        this.sendRatchet = new SymmRatchet(sharedSend);
        console.log('[Bob]\tSend ratchet seed:', b64(sharedSend));
        await this.saveToLocalStorage();
    }

    async receive_dhRatchet(alicePublic) {
        const dhRecv = await deriveKey(this.DHratchet.privateKey, alicePublic);
        const sharedRecv = (await this.rootRatchet.next(dhRecv))[0];
        this.recvRatchet = new SymmRatchet(sharedRecv);
        console.log('[Bob]\tRecv ratchet seed:', b64(sharedRecv));
        await this.saveToLocalStorage();
    }

    async send(msg) {
        await this.send_dhRatchet(this.receiver_public_key);
        const [key, iv] = await this.sendRatchet.next();
        const cipher = await encryptMessage(key, iv, msg);
        return {
            cipher: cipher.buffer,
            ratchet_key: await exportKey('raw', this.DHratchet.publicKey),
            key_version: this.version
        }
    }

    async sendImage(image, text) {
        await this.send_dhRatchet(this.receiver_public_key);
        const [key, iv] = await this.sendRatchet.next();
        let cipher = null;
        if (text) {
            cipher = await encryptMessage(key, iv, text);
        }
        const bytes_cipher = await encryptImage(key, iv, image);
        if (cipher) {
            cipher = cipher.buffer;
        }
        return {
            cipher: cipher,
            bytes_cipher: bytes_cipher.buffer,
            ratchet_key: await exportKey('raw', this.DHratchet.publicKey),
            key_version: this.version
        }
    }

    async recv(cipher) {
        await this.receive_dhRatchet(this.receiver_public_key);
        if (cipher) {
            const [key, iv] = await this.recvRatchet.next();
            try {
                return await decryptMessage(key, iv, cipher)
            } catch (error) {
                return `Failed to decrypt message: ${error}`;
            }
        }
    }

    async recvImage(bytes_cipher, text_cipher) {
        await this.receive_dhRatchet(this.receiver_public_key);
        if (bytes_cipher) {
            const [key, iv] = await this.recvRatchet.next();
            try {
                let text_message = null;
                if (text_cipher) {
                    text_message = await decryptMessage(key, iv, text_cipher);
                }

                let image_bytes = await decryptImage(key, iv, bytes_cipher);
                return {
                    text_message: text_message,
                    image_bytes: image_bytes
                }
            } catch (error) {
                return `Failed to decrypt message: ${error}`;
            }
        }
    }
}

class Alice {
    constructor(room, device_id, asymm) {
        this.IKa = {};
        this.EKa = {};
        this.DHratchet = {};
        this.receiver_public_key = null;
        this.room = room;
        this.device_id = device_id;
        this.version = null;
        this.asymm = asymm;
    }

    async setReceiverKey(key) {
        let public_key = base64StringToArrayBuffer(key);
        this.receiver_public_key = await crypto.subtle.importKey(
            'spki',
            public_key,
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            []
        );
    }

    async setReceiverKey_JWK(key) {
        const base64DecodedPublicKey = atob(key);
        const receivedJWK = JSON.parse(base64DecodedPublicKey);
        this.receiver_public_key = await crypto.subtle.importKey(
            'jwk',
            receivedJWK,
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            []
        );
    }

    async setReceiverKey_RAW(key) {
        this.receiver_public_key = await crypto.subtle.importKey(
            'raw',
            key,
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            []
        );
    }

    async x3dh(keys) {

        let ikkey = base64StringToArrayBuffer(keys[0]);
        let spkkey = base64StringToArrayBuffer(keys[1]);
        let opkey = base64StringToArrayBuffer(keys[2]);
        let IKb = await crypto.subtle.importKey(
            'spki',
            ikkey,
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            []
        );

        let SPKb = await crypto.subtle.importKey(
            'spki',
            spkkey,
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            []
        );

        let OPKb = await crypto.subtle.importKey(
            'spki',
            opkey,
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            []
        );

        const dh1 = await deriveKey(this.IKa.privateKey, SPKb);
        const dh2 = await deriveKey(this.EKa.privateKey, IKb);
        const dh3 = await deriveKey(this.EKa.privateKey, SPKb);
        const dh4 = await deriveKey(this.EKa.privateKey, OPKb);

        const dh1Bits = new Uint8Array(await exportKey('raw', dh1));
        const dh2Bits = new Uint8Array(await exportKey('raw', dh2));
        const dh3Bits = new Uint8Array(await exportKey('raw', dh3));
        const dh4Bits = new Uint8Array(await exportKey('raw', dh4));

        this.sk = await hkdf(new Uint8Array([...dh1Bits, ...dh2Bits, ...dh3Bits, ...dh4Bits]), 32);
        console.log('[alice]\tShared key:', b64(this.sk));
        await this.loadDhRatchetKey();
    }

    async initRatchets() {
        let currentSk = b64(this.sk);
        let previousSk = getSk(this.room, this.device_id, b64(this.sk));
        if (currentSk === previousSk) {
            let states = getRatchetState(this.room, this.device_id, b64(this.sk));

            if (states) {
                this.rootRatchet = new SymmRatchet(await this.asymm.decryptKeys(states.rootRatchetState));
                this.recvRatchet = new SymmRatchet(await this.asymm.decryptKeys(states.recvRatchetState));
                this.sendRatchet = new SymmRatchet(await this.asymm.decryptKeys(states.sendRatchetState));
            } else {
                this.rootRatchet = new SymmRatchet(this.sk);
                this.sendRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
                this.recvRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
            }
        } else {
            this.rootRatchet = new SymmRatchet(this.sk);
            this.sendRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
            this.recvRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
            saveSk(this.room, b64(this.sk), this.device_id);
            deleteRatchetStates(this.room, this.device_id, b64(this.sk));
        }
    }

    async loadDhRatchetKey() {
        let dhRatchetPrivateKey = await this.asymm.decryptKeys(getDHRatchetKey(this.room));
        this.DHratchet.privateKey = await crypto.subtle.importKey(
            'pkcs8',
            dhRatchetPrivateKey,
            {name: 'ECDH', namedCurve: 'P-256'},
            false,
            ['deriveKey']
        );
    }

    async retrieveAndImportKeys() {
        let roomData = getKeysByRoom(this.room);

        this.version = roomData.version;

        if (roomData && roomData.private_keys) {
            let ikPrivateKeyData = await this.asymm.decryptKeys(roomData.private_keys.ikPrivateKeyData);
            let ekPrivateKeyData = await this.asymm.decryptKeys(roomData.private_keys.ekPrivateKeyData);

            this.IKa.privateKey = await crypto.subtle.importKey(
                'pkcs8',
                ikPrivateKeyData,
                {name: 'ECDH', namedCurve: 'P-256'},
                false,
                ['deriveKey']
            );
            this.EKa.privateKey = await crypto.subtle.importKey(
                'pkcs8',
                ekPrivateKeyData,
                {name: 'ECDH', namedCurve: 'P-256'},
                false,
                ['deriveKey']
            );
        }
    }

    async saveToLocalStorage() {
        let root = b64(await this.asymm.encryptKeys(new Uint8Array(this.rootRatchet.state)));
        let recv = b64(await this.asymm.encryptKeys(new Uint8Array(this.recvRatchet.state)));
        let send = b64(await this.asymm.encryptKeys(new Uint8Array(this.sendRatchet.state)));

        saveRatchetState(this.room, this.device_id, b64(this.sk), root, recv, send);
    }

    async send_dhRatchet(bobPublic) {
        this.DHratchet = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );

        saveDHRatchetKey(b64(await this.asymm.encryptKeys(await exportKey('pkcs8', this.DHratchet.privateKey))), this.room);

        const dhSend = await deriveKey(this.DHratchet.privateKey, bobPublic);
        const sharedSend = (await this.rootRatchet.next(dhSend))[0];
        this.sendRatchet = new SymmRatchet(sharedSend);
        console.log('[Alice]\tSend ratchet seed:', b64(sharedSend));
        await this.saveToLocalStorage();
    }

    async receive_dhRatchet(bobPublic) {
        const dhRecv = await deriveKey(this.DHratchet.privateKey, bobPublic);
        const sharedRecv = (await this.rootRatchet.next(dhRecv))[0];
        this.recvRatchet = new SymmRatchet(sharedRecv);
        console.log('[Alice]\tRecv ratchet seed:', b64(sharedRecv));
        await this.saveToLocalStorage();
    }

    async send(msg) {
        await this.send_dhRatchet(this.receiver_public_key);
        const [key, iv] = await this.sendRatchet.next();
        const cipher = await encryptMessage(key, iv, msg);
        return {
            cipher: cipher.buffer,
            ratchet_key: await exportKey('raw', this.DHratchet.publicKey),
            key_version: this.version
        }
    }

    async sendImage(image, text) {
        await this.send_dhRatchet(this.receiver_public_key);
        const [key, iv] = await this.sendRatchet.next();
        let cipher = null;
        if (text) {
            cipher = await encryptMessage(key, iv, text);
        }
        const bytes_cipher = await encryptImage(key, iv, image);
        if (cipher) {
            cipher = cipher.buffer;
        }
        return {
            cipher: cipher,
            bytes_cipher: bytes_cipher.buffer,
            ratchet_key: await exportKey('raw', this.DHratchet.publicKey),
            key_version: this.version
        }
    }

    async recv(cipher) {
        await this.receive_dhRatchet(this.receiver_public_key);
        if (cipher) {
            const [key, iv] = await this.recvRatchet.next();
            try {
                return await decryptMessage(key, iv, cipher)
            } catch (error) {
                return `Failed to decrypt message: ${error}`;
            }
        }
    }

    async recvImage(bytes_cipher, text_cipher) {
        await this.receive_dhRatchet(this.receiver_public_key);
        if (bytes_cipher) {
            const [key, iv] = await this.recvRatchet.next();
            try {
                let text_message = null;
                if (text_cipher) {
                    text_message = await decryptMessage(key, iv, text_cipher);
                }

                let image_bytes = await decryptImage(key, iv, bytes_cipher);
                return {
                    text_message: text_message,
                    image_bytes: image_bytes
                }
            } catch (error) {
                return `Failed to decrypt message: ${error}`;
            }
        }
    }
}

// Section: Symmetric encryption
class symmetric {
    constructor() {
    }

    async importKey(asymm) {
        const self = this
        $.ajax({
            type: 'POST',
            url: 'get/private-keys/token/',
            xhrFields: {
                responseType: 'arraybuffer'  // Specify responseType as 'arraybuffer' to handle binary response
            },
            success: async function (response) {
                if (response) {
                    let data = msgpack.decode(new Uint8Array(response));
                    if (data) {
                        const token = new Uint8Array(32);
                        token.set(new Uint8Array(data.token), 0);
                        token.set(base64StringToUint8Array(getKeyToken()), 16);
                        let private_key = await window.crypto.subtle.importKey(
                            'raw',
                            token,
                            {name: 'AES-CBC'},
                            false,
                            ['decrypt']
                        );
                        await asymm.setPublicKey(data.public_key);
                        await asymm.importPrivateKey(await self.decryptAES(private_key, getSecondaryKey()));
                    }
                }
            },
            error: function (error) {
                console.error('Error:', error);
            }
        });
    }

    async decryptAES(private_key, data) {
        const combinedUint8 = base64StringToUint8Array(data);

        const iv = combinedUint8.slice(0, 16);
        const ciphertext = combinedUint8.slice(16);

        // Decrypt the ciphertext
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: 'AES-CBC',
                iv: iv
            },
            private_key,
            ciphertext
        );
        return new Uint8Array(decryptedData);
    }
}

// Section: Asymmetric encryption
class asymmetric {
    constructor(device_id) {
        this.public_key = null;
        this.device_id = device_id
        this.private_key = null;
    }

    async setReceiverKey(key) {
        try {
            let public_key = base64StringToArrayBuffer(key);
            this.public_key = await crypto.subtle.importKey(
                'spki',
                public_key,
                {
                    name: 'RSA-OAEP',
                    hash: {name: 'SHA-256'}
                },
                true,
                ['encrypt']
            );
        } catch (e) {
            console.error(e);
        }
    }

    async setPublicKey(key) {
        try {
            this.public_key = await crypto.subtle.importKey(
                'spki',
                key,
                {
                    name: 'RSA-OAEP',
                    hash: {name: 'SHA-256'}
                },
                true,
                ['encrypt']
            );
        } catch (e) {
            console.error(e);
        }
    }

    async encrypt(plaintext) {
        try {
            if (!this.public_key) {
                throw new Error('Public key not set.');
            }

            let plaintextBuffer = new TextEncoder().encode(plaintext);

            let iv = window.crypto.getRandomValues(new Uint8Array(12));

            // Generate a new AES key
            let aesKey = await window.crypto.subtle.generateKey(
                {name: 'AES-GCM', length: 256},
                true,
                ['encrypt', 'decrypt']
            );

            // Encrypt the plaintext with AES-GCM
            let ciphertext = await window.crypto.subtle.encrypt(
                {name: 'AES-GCM', iv: iv},
                aesKey,
                plaintextBuffer
            );

            let aesKeyBuffer = await window.crypto.subtle.exportKey('raw', aesKey);

            // Encrypt the AES key with RSA-OAEP
            let encryptedAesKey = await window.crypto.subtle.encrypt(
                {name: 'RSA-OAEP'},
                this.public_key,
                aesKeyBuffer
            );

            // Prepend IV to the ciphertext
            let ivAndCiphertext = new Uint8Array(iv.byteLength + ciphertext.byteLength);
            ivAndCiphertext.set(iv, 0);
            ivAndCiphertext.set(new Uint8Array(ciphertext), iv.byteLength);

            // Return the combined IV and ciphertext, and the encrypted AES key
            return {
                cipher: ivAndCiphertext,
                Aes: encryptedAesKey
            };
        } catch (e) {
            console.error(e);
        }
    }

    async encryptImageBytes(image_bytes, plaintext) {
        try {
            if (!this.public_key) {
                throw new Error('Public key not set.');
            }

            const imageArrayBuffer = await image_bytes.arrayBuffer();

            let iv = window.crypto.getRandomValues(new Uint8Array(12));

            let aesKey = await window.crypto.subtle.generateKey(
                {name: 'AES-GCM', length: 256},
                true,
                ['encrypt', 'decrypt']
            );

            let ciphertext;
            if (!plaintext) {
                plaintext = '';
            }

            let plaintextBuffer = new TextEncoder().encode(plaintext);
            ciphertext = await window.crypto.subtle.encrypt(
                {name: 'AES-GCM', iv: iv},
                aesKey,
                plaintextBuffer
            );

            let cipherbytes = await window.crypto.subtle.encrypt(
                {name: 'AES-GCM', iv: iv},
                aesKey,
                imageArrayBuffer
            );

            let aesKeyBuffer = await window.crypto.subtle.exportKey('raw', aesKey);

            let encryptedAesKey = await window.crypto.subtle.encrypt(
                {name: 'RSA-OAEP'},
                this.public_key,
                aesKeyBuffer
            );

            let ivAndCipherText = new Uint8Array(iv.byteLength + ciphertext.byteLength);
            ivAndCipherText.set(iv, 0);
            ivAndCipherText.set(new Uint8Array(ciphertext), iv.byteLength);
            return {
                ciphertext: ivAndCipherText,
                cipherbytes: cipherbytes,
                AES: encryptedAesKey
            };
        } catch (e) {
            console.error(e);
        }
    }

    async importPrivateKey(private_key_data) {
        this.private_key = await crypto.subtle.importKey(
            'pkcs8',
            private_key_data,
            {
                name: 'RSA-OAEP',
                hash: {name: 'SHA-256'}
            },
            false,
            ['decrypt']
        );
    }

    async encryptKeys(key) {
        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: 'RSA-OAEP',
            },
            this.public_key,
            key
        );

        return new Uint8Array(encryptedData);
    }

    async decryptKeys(cipher) {
        try {
            if (!this.private_key) {
                throw new Error('Private key not loaded.');
            }

            let decryptedKey = await window.crypto.subtle.decrypt(
                {name: 'RSA-OAEP'},
                this.private_key,
                base64StringToArrayBuffer(cipher)
            );

            return new Uint8Array(decryptedKey);
        } catch (e) {
            console.error(e);
        }
    }

    async decryptMessage(cipher, aes_key) {
        try {
            if (!this.private_key) {
                throw new Error('Private key not loaded.');
            }

            let iv = cipher.slice(0, 12);

            let ciphertext = cipher.slice(12);

            let aesKeyBuffer = await window.crypto.subtle.decrypt(
                {name: 'RSA-OAEP'},
                this.private_key,
                aes_key
            );

            let decryptedAesKey = await window.crypto.subtle.importKey(
                'raw',
                aesKeyBuffer,
                {name: 'AES-GCM'},
                true,
                ['encrypt', 'decrypt']
            );

            let decryptedPlaintext = await window.crypto.subtle.decrypt(
                {name: 'AES-GCM', iv: iv},
                decryptedAesKey,
                ciphertext
            );

            return new TextDecoder().decode(decryptedPlaintext);
        } catch (e) {
            console.error(e);
        }
    }

    async decrypt_Image_Message(cipher_bytes, cipher_text, aes_key) {
        try {
            if (!this.private_key) {
                throw new Error('Private key not loaded.');
            }

            let iv = cipher_text.slice(0, 12);

            let ciphertext = cipher_text.slice(12);

            // Decrypt the AES key using RSA-OAEP with the private key
            let aesKeyBuffer = await window.crypto.subtle.decrypt(
                {name: 'RSA-OAEP'},
                this.private_key,
                aes_key
            );

            let decryptedAesKey = await window.crypto.subtle.importKey(
                'raw',
                aesKeyBuffer,
                {name: 'AES-GCM'},
                true,
                ['encrypt', 'decrypt']
            );

            let decrypted_bytes = await window.crypto.subtle.decrypt(
                {name: 'AES-GCM', iv: iv},
                decryptedAesKey,
                cipher_bytes,
            );
            let decryptedPlaintext = await window.crypto.subtle.decrypt(
                {name: 'AES-GCM', iv: iv},
                decryptedAesKey,
                ciphertext,
            );

            decryptedPlaintext = new TextDecoder().decode(decryptedPlaintext);

            if (decryptedPlaintext === '') {
                decryptedPlaintext = null;
            }

            return {
                text_message: decryptedPlaintext,
                cipher_bytes: new Uint8Array(decrypted_bytes)
            };
        } catch (e) {
            console.error(`Error: ${e}`);
        }
    }
}

// Section: Save keys
function saveKeys_sender(room, version_int, ik_private_key, ek_private_key, dhratchet_private_key) {
    let roomData = JSON.parse(localStorage.getItem('ratchet')) || {};

    roomData[room] = roomData[room] || {};

    roomData[room].type = 'sender';

    roomData[room].version = version_int;

    roomData[room].private_keys = {
        ikPrivateKeyData: ik_private_key,
        ekPrivateKeyData: ek_private_key,
        dhratchet_key: dhratchet_private_key
    };

    localStorage.setItem('ratchet', JSON.stringify(roomData));
}

function saveKeys_receiver(room, version_int, ik_private_key, spk_private_key, opk_private_key, dhratchet_key) {

    let roomData = JSON.parse(localStorage.getItem('ratchet')) || {};

    roomData[room] = roomData[room] || {};

    roomData[room].type = 'receiver';

    roomData[room].version = version_int;

    roomData[room].private_keys = {
        ikPrivateKey: ik_private_key,
        spkPrivateKey: spk_private_key,
        opkPrivateKey: opk_private_key,
        dhratchet_key: dhratchet_key
    };

    localStorage.setItem('ratchet', JSON.stringify(roomData));
}

function getKeysByRoom(room) {
    let ratchetData = JSON.parse(localStorage.getItem('ratchet')) || {};

    if (ratchetData[room]) {
        return ratchetData[room];
    } else {
        return null;
    }
}

function saveRatchetState(room, device_id, sk, rootRatchetState, recvRatchetState, sendRatchetState) {
    let ratchetData = JSON.parse(localStorage.getItem('ratchet')) || {};

    if (!ratchetData[room]) {
        ratchetData[room] = {};
    }

    if (!ratchetData[room][device_id]) {
        ratchetData[room][device_id] = {};
    }

    if (!ratchetData[room][device_id][sk]) {
        ratchetData[room][device_id][sk] = {};
    }

    ratchetData[room][device_id][sk].rootRatchetState = rootRatchetState;
    ratchetData[room][device_id][sk].recvRatchetState = recvRatchetState;
    ratchetData[room][device_id][sk].sendRatchetState = sendRatchetState;

    localStorage.setItem('ratchet', JSON.stringify(ratchetData));
}

function getRatchetState(room, device_id, sk) {
    const ratchetData = JSON.parse(localStorage.getItem('ratchet')) || {};

    if (!ratchetData[room]) {
        ratchetData[room] = {};
    }

    if (!ratchetData[room][device_id]) {
        ratchetData[room][device_id] = {};
    }

    if (!ratchetData[room][device_id][sk]) {
        ratchetData[room][device_id][sk] = {};
    }

    let root = ratchetData[room][device_id][sk].rootRatchetState;
    let recv = ratchetData[room][device_id][sk].recvRatchetState;
    let send = ratchetData[room][device_id][sk].sendRatchetState;

    if (root && recv && send) {
        const rootRatchetState = root
        const recvRatchetState = recv
        const sendRatchetState = send

        return {
            rootRatchetState,
            recvRatchetState,
            sendRatchetState,
        };
    } else {
        return null;
    }
}

function deleteRatchetStates(room, device_id, sk) {
    let ratchetData = JSON.parse(localStorage.getItem('ratchet')) || {};

    if (!ratchetData[room]) {
        ratchetData[room] = {};
    }

    if (!ratchetData[room][device_id]) {
        ratchetData[room][device_id] = {};
    }

    if (!ratchetData[room][device_id][sk]) {
        ratchetData[room][device_id][sk] = {};
    }

    if (ratchetData[room]) {
        delete ratchetData[room][device_id][sk].rootRatchetState;
        delete ratchetData[room][device_id][sk].recvRatchetState;
        delete ratchetData[room][device_id][sk].sendRatchetState;

        localStorage.setItem('ratchet', JSON.stringify(ratchetData));
    }
}

function saveDHRatchetKey(dhratchet_private_key, room) {
    let ratchetData = JSON.parse(localStorage.getItem('ratchet')) || {};

    if (!ratchetData[room]) {
        ratchetData[room] = {};
    }

    ratchetData[room].private_keys.dhratchet_key = dhratchet_private_key;

    localStorage.setItem('ratchet', JSON.stringify(ratchetData));
}

function getDHRatchetKey(room) {
    let ratchetData = JSON.parse(localStorage.getItem('ratchet')) || {};

    if (!ratchetData[room]) {
        ratchetData[room] = {};
    }

    if (ratchetData[room].private_keys.dhratchet_key) {
        return ratchetData[room].private_keys.dhratchet_key;
    } else {
        return null;
    }
}

function saveSk(room, sk, device_id) {
    let ratchetData = JSON.parse(localStorage.getItem('ratchet')) || {};

    if (!ratchetData[room]) {
        ratchetData[room] = {};
    }

    if (!ratchetData[room][device_id]) {
        ratchetData[room][device_id] = {};
    }

    if (!ratchetData[room][device_id][sk]) {
        ratchetData[room][device_id][sk] = {};
    }

    ratchetData[room][device_id][sk].sk = JSON.stringify(sk);

    localStorage.setItem('ratchet', JSON.stringify(ratchetData));
}

function getSk(room, device_id, sk) {
    let ratchetData = JSON.parse(localStorage.getItem('ratchet')) || {};

    if (!ratchetData[room]) {
        ratchetData[room] = {};
    }

    if (!ratchetData[room][device_id]) {
        ratchetData[room][device_id] = {};
    }

    if (!ratchetData[room][device_id][sk]) {
        ratchetData[room][device_id][sk] = {};
    }

    if (ratchetData[room][device_id][sk].sk) {
        return JSON.parse(ratchetData[room][device_id][sk].sk);
    } else {
        return null;
    }
}

function saveSecondaryKey(key, token) {
    if (key) {
        let storage = JSON.parse(localStorage.getItem('secondary_key')) || {};

        if (!storage['key']) {
            storage['key'] = {};
        }

        storage.key = key;
        storage.token = token;

        localStorage.setItem('secondary_key', JSON.stringify(storage));
    }
}

function getSecondaryKey() {
    let storage = JSON.parse(localStorage.getItem('secondary_key')) || {};

    if (storage.key) {
        return storage.key;
    } else {
        return null;
    }
}

function getKeyToken() {
    let storage = JSON.parse(localStorage.getItem('secondary_key')) || {};

    if (storage.token) {
        return storage.token;
    } else {
        return null;
    }
}