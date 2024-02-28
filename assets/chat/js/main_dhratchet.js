async function importKey(key, usage) {
    return await crypto.subtle.importKey(
        'raw',
        key,
        {name: 'HKDF'},
        false,
        usage
    )
}

async function importKey_ECDH(format, key, usage) {
    return await crypto.subtle.importKey(
        format,
        key,
        {name: 'ECDH', namedCurve: 'P-256'},
        true,
        usage
    );
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
    // Import the key as a spki buffer
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


    // Decrypt the message using AES-GCM
    const decrypted = await crypto.subtle.decrypt(
        {name: 'AES-GCM', iv},
        aesKey,
        encryptedMessage
    );

    // Decode the decrypted message
    return new TextDecoder().decode(decrypted);
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

    async next(inp = new Uint8Array()) {
        const stateArray = new Uint8Array(this.state);
        const inputArray = new Uint8Array(inp);

        const concatenatedData = new Uint8Array(stateArray.length + inputArray.length);
        concatenatedData.set(stateArray, 0);
        concatenatedData.set(inputArray, stateArray.length);

        const cryptoKey = await importKey(concatenatedData, ['deriveBits'])

        // Derive 80 bytes using HKDF
        const derivedBits = await crypto.subtle.deriveBits(
            {name: 'HKDF', hash: 'SHA-256', info: new Uint8Array(), salt: new Uint8Array()},
            cryptoKey,
            80 * 8
        );

        const derivedArray = new Uint8Array(derivedBits);
        this.state = derivedArray.slice(0, 32)
        const outKey = derivedArray.slice(32, 64);
        const iv = derivedArray.slice(64, 80);

        return [outKey, iv];
    }
}

class Bob {
    constructor() {
        this.IKb = {};
        this.SPKb = {};
        this.OPKb = {};
        this.DHratchet = {};
    }

    async generateKeys() {
        this.IKb = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );
        this.SPKb = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );
        this.OPKb = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );
        this.DHratchet = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );

        await this.saveDhratchetKey();
    }

    async x3dh(alice) {
        const dh1 = await deriveKey(this.SPKb.privateKey, alice.IKa.publicKey);
        const dh2 = await deriveKey(this.IKb.privateKey, alice.EKa.publicKey);
        const dh3 = await deriveKey(this.SPKb.privateKey, alice.EKa.publicKey);
        const dh4 = await deriveKey(this.OPKb.privateKey, alice.EKa.publicKey);

        const dh1Bits = new Uint8Array(await exportKey('raw', dh1));
        const dh2Bits = new Uint8Array(await exportKey('raw', dh2));
        const dh3Bits = new Uint8Array(await exportKey('raw', dh3));
        const dh4Bits = new Uint8Array(await exportKey('raw', dh4));

        this.sk = await hkdf(new Uint8Array([...dh1Bits, ...dh2Bits, ...dh3Bits, ...dh4Bits]), 32);
        console.log('[Bob]\tShared key:', b64(this.sk));
    }

    async saveToLocalStorage() {
        // Storing the keys
        let ikbKey = await exportKey('jwk', this.IKb.privateKey);
        let spkbKey = await exportKey('jwk', this.SPKb.privateKey);
        let opkbKey = await exportKey('jwk', this.OPKb.privateKey);

        let ikbKeypublic = await exportKey('jwk', this.IKb.publicKey);
        let spkbKeypublic = await exportKey('jwk', this.SPKb.publicKey);
        let opkbKeypublic = await exportKey('jwk', this.OPKb.publicKey);

        let keys = {
            'ikbKey': ikbKey,
            'spkbKey': spkbKey,
            'opkbKey': opkbKey,
            'ikbKeypublic': ikbKeypublic,
            'spkbKeypublic': spkbKeypublic,
            'opkbKeypublic': opkbKeypublic,
        };

        localStorage.setItem('keys', JSON.stringify(keys));

        // localStorage.setItem('rootRatchetState', btoa(String.fromCharCode.apply(null, new Uint8Array(this.rootRatchet.state))));
        // localStorage.setItem('recvRatchetState', btoa(String.fromCharCode.apply(null, new Uint8Array(this.recvRatchet.state))));
        // localStorage.setItem('sendRatchetState', btoa(String.fromCharCode.apply(null, new Uint8Array(this.sendRatchet.state))));
    }

    async saveDhratchetKey() {
        let dhRatchetPrivateKey = await exportKey('jwk', this.DHratchet.privateKey);
        let dhRatchetPublicKey = await exportKey('jwk', this.DHratchet.publicKey);
        let keys = {
            'dhRatchetPrivateKey': dhRatchetPrivateKey,
            'dhRatchetPublicKey': dhRatchetPublicKey,
        };

        localStorage.setItem('dhratchetKeys', JSON.stringify(keys));
    }

    async loadDhratchetKey() {
        let retrievedKeys = JSON.parse(localStorage.getItem('dhratchetKeys'));
        this.DHratchet.privateKey = await importKey_ECDH(
            'jwk',
            retrievedKeys.dhRatchetPrivateKey,
            ['deriveKey']
        );
        this.DHratchet.publicKey = await importKey_ECDH(
            'jwk',
            retrievedKeys.dhRatchetPublicKey,
            []
        );
    }

    async loadFromLocalStorage() {
        try {
            let retrievedKeys = JSON.parse(localStorage.getItem('keys'));

            this.IKb.privateKey = await importKey_ECDH(
                'jwk',
                retrievedKeys.ikbKey,
                ['deriveKey']
            );
            this.SPKb.privateKey = await importKey_ECDH(
                'jwk',
                retrievedKeys.spkbKey,
                ['deriveKey']
            );
            this.OPKb.privateKey = await importKey_ECDH(
                'jwk',
                retrievedKeys.opkbKey,
                ['deriveKey']
            );

            this.IKb.publicKey = await importKey_ECDH(
                'jwk',
                retrievedKeys.ikbKeypublic,
                []
            );
            this.SPKb.publicKey = await importKey_ECDH(
                'jwk',
                retrievedKeys.spkbKeypublic,
                []
            );
            this.OPKb.publicKey = await importKey_ECDH(
                'jwk',
                retrievedKeys.opkbKeypublic,
                []
            );

            // Retrieving the states
            let retrievedRootRatchetState = new Uint8Array(atob(localStorage.getItem('rootRatchetState')).split("").map(function (c) {
                return c.charCodeAt(0);
            }));
            let retrievedRecvRatchetState = new Uint8Array(atob(localStorage.getItem('recvRatchetState')).split("").map(function (c) {
                return c.charCodeAt(0);
            }));
            let retrievedSendRatchetState = new Uint8Array(atob(localStorage.getItem('sendRatchetState')).split("").map(function (c) {
                return c.charCodeAt(0);
            }));

            this.rootRatchet = new SymmRatchet(retrievedRootRatchetState);
            this.recvRatchet = new SymmRatchet(retrievedRecvRatchetState);
            this.sendRatchet = new SymmRatchet(retrievedSendRatchetState);
        } catch (error) {
            console.error("Error", error);
        }
    }


    async initRatchets() {
        this.rootRatchet = new SymmRatchet(this.sk);
        this.recvRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
        this.sendRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
    }

    async send_dhRatchet(alicePublic) {
        this.DHratchet = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );

        await this.saveDhratchetKey();

        const dhSend = await deriveKey(this.DHratchet.privateKey, alicePublic);
        const sharedSend = (await this.rootRatchet.next(dhSend))[0];
        this.sendRatchet = new SymmRatchet(sharedSend);
        console.log('[Bob]\tSend ratchet seed:', b64(sharedSend));
    }

    async receive_dhRatchet(alicePublic) {
        const dhRecv = await deriveKey(this.DHratchet.privateKey, alicePublic);
        const sharedRecv = (await this.rootRatchet.next(dhRecv))[0];
        this.recvRatchet = new SymmRatchet(sharedRecv);
        console.log('[Bob]\tRecv ratchet seed:', b64(sharedRecv));
    }

    async send(alice, msg) {
        await this.send_dhRatchet(alice.DHratchet.publicKey);
        const [key, iv] = await this.sendRatchet.next();
        const cipher = await encryptMessage(key, iv, msg);
        console.log('[Bob]\tSending ciphertext to Alice:', b64(cipher));
        await alice.recv(cipher, this.DHratchet.publicKey);
    }

    async recv(cipher, alicePublicKey) {
        await this.receive_dhRatchet(alicePublicKey);
        const [key, iv] = await this.recvRatchet.next();
        try {
            const decrypted = await decryptMessage(key, iv, cipher);
            console.log('[Bob]\tDecrypted message:', decrypted);
        } catch (error) {
            console.error('Error during decryption:', error);
        }
    }
}

class Alice {

    constructor() {
        this.IKa = {};
        this.EKa = {};
        this.DHratchet = null;
    }

    async generate_keys() {
        this.IKa = null;
        this.EKa = null;

        this.IKa = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );
        this.EKa = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );
        this.DHratchet = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );
    }

    async x3dh(bob) {

        const dh1 = await deriveKey(this.IKa.privateKey, bob.SPKb.publicKey);
        const dh2 = await deriveKey(this.EKa.privateKey, bob.IKb.publicKey);
        const dh3 = await deriveKey(this.EKa.privateKey, bob.SPKb.publicKey);
        const dh4 = await deriveKey(this.EKa.privateKey, bob.OPKb.publicKey);
        // Use the derived keys directly in the HKDF

        // Use the derived keys directly in the HKDF
        const dh1Bits = new Uint8Array(await exportKey('raw', dh1));
        const dh2Bits = new Uint8Array(await exportKey('raw', dh2));
        const dh3Bits = new Uint8Array(await exportKey('raw', dh3));
        const dh4Bits = new Uint8Array(await exportKey('raw', dh4));

        this.sk = await hkdf(new Uint8Array([...dh1Bits, ...dh2Bits, ...dh3Bits, ...dh4Bits]), 32);
        console.log('[alice]\tShared key:', b64(this.sk));
    }

    async initRatchets() {
        this.rootRatchet = new SymmRatchet(this.sk);
        this.sendRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
        this.recvRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
    }

    async saveToLocalStorage() {
        // Storing the keys
        let ikaKey = await exportKey('jwk', this.IKa.privateKey);
        let ekaKey = await exportKey('jwk', this.EKa.privateKey);

        let ikaKeypublic = await exportKey('jwk', this.IKa.publicKey);
        let ekaKeypublic = await exportKey('jwk', this.EKa.publicKey);

        let keys = {
            'ikaKey': ikaKey,
            'ekaKey': ekaKey,
            'ikaKeypublic': ikaKeypublic,
            'ekaKeypublic': ekaKeypublic,
        };

        localStorage.setItem('alice_keys', JSON.stringify(keys));

        localStorage.setItem('alice_rootRatchetState', btoa(String.fromCharCode.apply(null, new Uint8Array(this.rootRatchet.state))));
        localStorage.setItem('alice_recvRatchetState', btoa(String.fromCharCode.apply(null, new Uint8Array(this.recvRatchet.state))));
        localStorage.setItem('alice_sendRatchetState', btoa(String.fromCharCode.apply(null, new Uint8Array(this.sendRatchet.state))));
    }

    async loadFromLocalStorage() {
        try {
            let retrievedKeys = JSON.parse(localStorage.getItem('alice_keys'));

            this.IKa.privateKey = await importKey_ECDH(
                'jwk',
                retrievedKeys.ikaKey,
                ['deriveKey']
            );
            this.EKa.privateKey = await importKey_ECDH(
                'jwk',
                retrievedKeys.ekaKey,
                ['deriveKey']
            );

            this.IKa.publicKey = await importKey_ECDH(
                'jwk',
                retrievedKeys.ikaKeypublic,
                []
            );
            this.EKa.publicKey = await importKey_ECDH(
                'jwk',
                retrievedKeys.ekaKeypublic,
                []
            );

            // Retrieving the states
            let retrievedRootRatchetState = new Uint8Array(atob(localStorage.getItem('alice_rootRatchetState')).split("").map(function (c) {
                return c.charCodeAt(0);
            }));
            let retrievedRecvRatchetState = new Uint8Array(atob(localStorage.getItem('alice_recvRatchetState')).split("").map(function (c) {
                return c.charCodeAt(0);
            }));
            let retrievedSendRatchetState = new Uint8Array(atob(localStorage.getItem('alice_sendRatchetState')).split("").map(function (c) {
                return c.charCodeAt(0);
            }));

            this.rootRatchet = new SymmRatchet(retrievedRootRatchetState);
            this.recvRatchet = new SymmRatchet(retrievedRecvRatchetState);
            this.sendRatchet = new SymmRatchet(retrievedSendRatchetState);
        } catch (error) {
            console.error("Error", error);
        }
    }

    async send_dhRatchet(bobPublic) {
        this.DHratchet = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );

        const dhSend = await deriveKey(this.DHratchet.privateKey, bobPublic);
        const sharedSend = (await this.rootRatchet.next(dhSend))[0];
        this.sendRatchet = new SymmRatchet(sharedSend);
        console.log('[Alice]\tSend ratchet seed:', b64(sharedSend));
    }

    async receive_dhRatchet(bobPublic) {
        const dhRecv = await deriveKey(this.DHratchet.privateKey, bobPublic);
        const sharedRecv = (await this.rootRatchet.next(dhRecv))[0];
        this.recvRatchet = new SymmRatchet(sharedRecv);
        console.log('[Alice]\tRecv ratchet seed:', b64(sharedRecv));
    }

    async send(bob, msg) {
        await this.send_dhRatchet(bob.DHratchet.publicKey)
        const [key, iv] = await this.sendRatchet.next();
        const cipher = await encryptMessage(key, iv, msg);
        console.log('[Alice]\tSending ciphertext to Bob:', b64(cipher));
        await bob.recv(cipher, this.DHratchet.publicKey);
    }

    async recv(cipher, bobPublicKey) {
        await this.receive_dhRatchet(bobPublicKey);
        const [key, iv] = await this.recvRatchet.next();
        try {
            const decrypted = await decryptMessage(key, iv, cipher);
            console.log('[Alice]\tDecrypted message:', decrypted);
        } catch (error) {
            console.error('Error during decryption:', error);
        }
    }
}

(async () => {
    const alice = new Alice();
    const bob = new Bob();
    await alice.generate_keys();
    await bob.generateKeys();
    // await bob.loadFromLocalStorage();
    // await alice.loadFromLocalStorage();

    await alice.x3dh(bob);
    await bob.x3dh(alice);

    await alice.initRatchets();
    await bob.initRatchets();

    // Alice's sending ratchet is initialized with Bob's public key
    // await bob.loadDhratchetKey();
    // console.log(bob.DHratchet.publicKey)

    await bob.send(alice, 'Hello to you too, Alice!');

    await alice.send(bob, 'Hello Bob!');

    // await bob.saveToLocalStorage();
    // await alice.saveToLocalStorage();
    // await bob.saveDhratchetKey();
})();