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
    constructor(username, room) {
        this.IKb = {};
        this.SPKb = {};
        this.OPKb = {};
        this.DHratchet = {};
        this.username = username;
        this.receiver_public_key = null;
        this.room = room;
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
    }

    async retrieveAndImportKeys() {
        let roomData = getKeysByRoom(this.room);

        if (roomData && roomData.type && roomData.private_keys) {
            let ikPrivateKey = JSON.parse(roomData.private_keys.ikPrivateKey);
            let spkPrivateKey = JSON.parse(roomData.private_keys.spkPrivateKey);
            let opkPrivateKey = JSON.parse(roomData.private_keys.opkPrivateKey);
            let dhratchet_privateKey = JSON.parse(roomData.private_keys.dhratchet_key);

            this.IKb.privateKey = await crypto.subtle.importKey(
                'jwk',
                ikPrivateKey,
                {name: 'ECDH', namedCurve: 'P-256'},
                false,
                ['deriveKey']
            );
            this.SPKb.privateKey = await crypto.subtle.importKey(
                'jwk',
                spkPrivateKey,
                {name: 'ECDH', namedCurve: 'P-256'},
                false,
                ['deriveKey']
            );

            this.OPKb.privateKey = await crypto.subtle.importKey(
                'jwk',
                opkPrivateKey,
                {name: 'ECDH', namedCurve: 'P-256'},
                false,
                ['deriveKey']
            );

            this.DHratchet.privateKey = await crypto.subtle.importKey(
                'jwk',
                dhratchet_privateKey,
                {name: 'ECDH', namedCurve: 'P-256'},
                false,
                ['deriveKey']
            );
        }
    }

    async saveToLocalStorage() {
        let root = btoa(String.fromCharCode.apply(null, new Uint8Array(this.rootRatchet.state)));
        let recv = btoa(String.fromCharCode.apply(null, new Uint8Array(this.recvRatchet.state)));
        let send =  btoa(String.fromCharCode.apply(null, new Uint8Array(this.sendRatchet.state)));
        saveRatchetState(this.room, root, recv, send);
    }

    removeFromLocalStorage() {
        deleteRatchetStates(this.room);
    }

    async loadFromLocalStorage() {
        let states = getRatchetState(this.room);

        this.rootRatchet = new SymmRatchet(states.rootRatchetState);
        this.recvRatchet = new SymmRatchet(states.recvRatchetState);
        this.sendRatchet = new SymmRatchet(states.sendRatchetState);
    }

    async initRatchets(is_new) {
        let retrievedRootRatchetState = new Uint8Array(atob(localStorage.getItem('rootRatchetState')).split("").map(function (c) {
            return c.charCodeAt(0);
        }));

        if (is_new) {
            console.log('1');
            this.rootRatchet = new SymmRatchet(this.sk);
            this.recvRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
            this.sendRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
            this.removeFromLocalStorage();
        } else if (retrievedRootRatchetState) {
            console.log('2');
            await this.loadFromLocalStorage();
        } else {
            console.log('3');
            this.rootRatchet = new SymmRatchet(this.sk);
            this.recvRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
            this.sendRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
        }
    }

    async send_dhRatchet(alicePublic) {
        this.DHratchet = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );

        saveDHRatchetKey(await exportKey('jwk', this.DHratchet.privateKey), this.username);

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

    async send(alice_public_key, msg) {
        await this.send_dhRatchet(alice_public_key);
        const [key, iv] = await this.sendRatchet.next();
        const cipher = await encryptMessage(key, iv, msg);
        return {
            cipher: b64(cipher),
            ratchet_key: btoa(JSON.stringify(await exportKey('jwk', this.DHratchet.publicKey)))
        }
    }

    async recv(cipher, alicePublicKey) {
        await this.receive_dhRatchet(alicePublicKey);
        const [key, iv] = await this.recvRatchet.next();
        try {
            const arrayBufferCipher = new Uint8Array([...atob(cipher)].map(char => char.charCodeAt(0)));
            return await decryptMessage(key, iv, arrayBufferCipher)
        } catch (error) {
            return `Failed to decrypt message: ${error}`;
        }
    }
}

class Alice {
    constructor(username, room) {
        this.IKa = {};
        this.EKa = {};
        this.DHratchet = {};
        this.username = username;
        this.receiver_public_key = null;
        this.room = room;
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
    }

    async initRatchets(is_new) {
        let retrievedRootRatchetState = new Uint8Array(atob(localStorage.getItem('alice_rootRatchetState')).split("").map(function (c) {
            return c.charCodeAt(0);
        }));
        if (is_new) {
            this.rootRatchet = new SymmRatchet(this.sk);
            this.sendRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
            this.recvRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
            this.removeFromLocalStorage();
        } else if (retrievedRootRatchetState) {
            await this.loadFromLocalStorage();
        } else {
            this.rootRatchet = new SymmRatchet(this.sk);
            this.sendRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
            this.recvRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
        }
    }

    async retrieveAndImportKeys() {
        let roomData = getKeysByRoom(this.room);

        if (roomData && roomData.type && roomData.private_keys) {
            let ikPrivateKeyData = JSON.parse(roomData.private_keys.ikPrivateKeyData);
            let ekPrivateKeyData = JSON.parse(roomData.private_keys.ekPrivateKeyData);
            let dhRatchetPrivateKey = JSON.parse(roomData.private_keys.dhratchet_key);

            this.IKa.privateKey = await crypto.subtle.importKey(
                'jwk',
                ikPrivateKeyData,
                {name: 'ECDH', namedCurve: 'P-256'},
                false,
                ['deriveKey']
            );
            this.EKa.privateKey = await crypto.subtle.importKey(
                'jwk',
                ekPrivateKeyData,
                {name: 'ECDH', namedCurve: 'P-256'},
                false,
                ['deriveKey']
            );

            this.DHratchet.privateKey = await crypto.subtle.importKey(
                'jwk',
                dhRatchetPrivateKey,
                {name: 'ECDH', namedCurve: 'P-256'},
                false,
                ['deriveKey']
            );
        }
    }

    async saveToLocalStorage() {
        let root = btoa(String.fromCharCode.apply(null, new Uint8Array(this.rootRatchet.state)));
        let recv = btoa(String.fromCharCode.apply(null, new Uint8Array(this.recvRatchet.state)));
        let send =  btoa(String.fromCharCode.apply(null, new Uint8Array(this.sendRatchet.state)));
        saveRatchetState(this.room, root, recv, send);
    }

    removeFromLocalStorage() {
        deleteRatchetStates(this.room);
    }

    async loadFromLocalStorage() {
        let states = getRatchetState(this.room);

        this.rootRatchet = new SymmRatchet(states.rootRatchetState);
        this.recvRatchet = new SymmRatchet(states.recvRatchetState);
        this.sendRatchet = new SymmRatchet(states.sendRatchetState);
    }

    async send_dhRatchet(bobPublic) {
        this.DHratchet = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );

        saveDHRatchetKey(await exportKey('jwk', this.DHratchet.privateKey), this.username);

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

    async send(bob_public_key, msg) {
        await this.send_dhRatchet(bob_public_key)
        const [key, iv] = await this.sendRatchet.next();
        const cipher = await encryptMessage(key, iv, msg);
        return {
            cipher: b64(cipher),
            ratchet_key: btoa(JSON.stringify(await exportKey('jwk', this.DHratchet.publicKey)))
        }
    }

    async recv(cipher, bobPublicKey) {
        await this.receive_dhRatchet(bobPublicKey);
        const [key, iv] = await this.recvRatchet.next();
        try {
            const arrayBufferCipher = new Uint8Array([...atob(cipher)].map(char => char.charCodeAt(0)));
            return await decryptMessage(key, iv, arrayBufferCipher)
        } catch (error) {
            return `Failed to decrypt message: ${error}`;
        }
    }
}

// Section: Save keys
function saveKeys_sender(room, ik_private_key, ek_private_key, dhratchet_private_key) {
    let roomData = JSON.parse(localStorage.getItem('ratchet')) || {};

    if (!roomData[room]) {
        roomData[room] = {};
    }

    roomData[room].type = 'sender';

    roomData[room].private_keys = {
        ikPrivateKeyData: ik_private_key,
        ekPrivateKeyData: ek_private_key,
        dhratchet_key: dhratchet_private_key
    };

    localStorage.setItem('ratchet', JSON.stringify(roomData));
}

function saveKeys_receiver(room, ik_private_key, spk_private_key, opk_private_key, dhratchet_key) {

    let roomData = JSON.parse(localStorage.getItem('ratchet')) || {};

    if (!roomData[room]) {
        roomData[room] = {};
    }

    roomData[room].type = 'receiver';

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
        return null; // or handle the case when the room data is not found
    }
}

function saveRatchetState(room, rootRatchetState, recvRatchetState, sendRatchetState) {
    let ratchetData = JSON.parse(localStorage.getItem('ratchet')) || {};

    ratchetData[room].rootRatchetState = btoa(String.fromCharCode.apply(null, new Uint8Array(rootRatchetState)));
    ratchetData[room].recvRatchetState = btoa(String.fromCharCode.apply(null, new Uint8Array(recvRatchetState)));
    ratchetData[room].sendRatchetState = btoa(String.fromCharCode.apply(null, new Uint8Array(sendRatchetState)));
}

function getRatchetState(room) {
    const ratchetData = JSON.parse(localStorage.getItem('ratchet')) || {};

    if (ratchetData[room]) {
        const rootRatchetState = new Uint8Array(Array.from(atob(ratchetData[room].rootRatchetState), (c) => c.charCodeAt(0)));
        const recvRatchetState = new Uint8Array(Array.from(atob(ratchetData[room].recvRatchetState), (c) => c.charCodeAt(0)));
        const sendRatchetState = new Uint8Array(Array.from(atob(ratchetData[room].sendRatchetState), (c) => c.charCodeAt(0)));

        return {
            rootRatchetState,
            recvRatchetState,
            sendRatchetState,
        };
    } else {
        return null; // or handle the case when the room data is not found
    }
}

function deleteRatchetStates(room) {
    let ratchetData = JSON.parse(localStorage.getItem('ratchet')) || {};

    if (ratchetData[room]) {
        delete ratchetData[room].rootRatchetState;
        delete ratchetData[room].recvRatchetState;
        delete ratchetData[room].sendRatchetState;

        localStorage.setItem('ratchet', JSON.stringify(ratchetData));
    }
}

function saveDHRatchetKey(dhratchet_private_key, room) {
    let ratchetData = JSON.parse(localStorage.getItem('ratchet')) || {};

    if (!ratchetData[room]) {
        ratchetData[room] = {};
    }

    ratchetData[room].private_keys['dhratchet_key'] = JSON.stringify(dhratchet_private_key);

    localStorage.setItem(room, JSON.stringify(ratchetData));
}