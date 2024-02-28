
class Bob {
    constructor() {
        // generate Bob's keys
        this.IKb = null;
        this.SPKb = null;
        this.OPKb = null;
        this.DHratchet = null;
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

    }

    async x3dh(alice) {
        const dh1 = await deriveKey(alice.IKa.privateKey, this.SPKb.publicKey);
        const dh2 = await deriveKey(alice.EKa.privateKey, this.IKb.publicKey);
        const dh3 = await deriveKey(alice.EKa.privateKey, this.SPKb.publicKey);
        const dh4 = await deriveKey(alice.EKa.privateKey, this.OPKb.publicKey);

        // Use the derived keys directly in the HKDF
        const dh1Bits = new Uint8Array(await exportKey('raw', dh1));
        const dh2Bits = new Uint8Array(await exportKey('raw', dh2));
        const dh3Bits = new Uint8Array(await exportKey('raw', dh3));
        const dh4Bits = new Uint8Array(await exportKey('raw', dh4));

        this.sk = await hkdf(new Uint8Array([...dh1Bits, ...dh2Bits, ...dh3Bits, ...dh4Bits]), 32);
        console.log('[Bob]\tShared key:', b64(this.sk));
    }

    async initRatchets() {
        this.rootRatchet = new SymmRatchet(this.sk);
        this.recvRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
        this.sendRatchet = new SymmRatchet((await this.rootRatchet.next())[0]);
    }

    async dhRatchet(alicePublic) {
        const dhRecv = await deriveKey(this.DHratchet.privateKey, alicePublic);
        const sharedRecv = (await this.rootRatchet.next(dhRecv))[0];
        this.recvRatchet = new SymmRatchet(sharedRecv);
        console.log('[Bob]\tRecv ratchet seed:', b64(sharedRecv));

        this.DHratchet = await crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );

        const dhSend = await deriveKey(this.DHratchet.privateKey, alicePublic);
        const sharedSend = (await this.rootRatchet.next(dhSend))[0];
        this.sendRatchet = new SymmRatchet(sharedSend);
        console.log('[Bob]\tSend ratchet seed:', b64(sharedSend));
    }

    async send(alice, msg) {
        const [key, iv] = await this.sendRatchet.next();
        const cipher = await encryptMessage(key, iv, msg);
        console.log('[Bob]\tSending ciphertext to Alice:', b64(cipher));
        alice.recv(cipher, this.DHratchet.publicKey);
    }

    async recv(cipher, alicePublicKey) {
        await this.dhRatchet(alicePublicKey);
        const [key, iv] = await this.recvRatchet.next();
        try {
            const decrypted = await decryptMessage(key, iv, cipher);
            console.log('[Bob]\tDecrypted message:', decrypted);
        } catch (error) {
            console.error('Error during decryption:', error);
        }
    }
}