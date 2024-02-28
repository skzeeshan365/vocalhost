
class Alice {

    constructor() {
        this.IKa = null;
        this.EKa = null;
        this.DHratchet = null;
    }

    async generate_keys() {
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

    async dhRatchet(bobPublic) {
        if (this.DHratchet !== null) {
            const dhRecv = await deriveKey(this.DHratchet.privateKey, bobPublic);
            const sharedRecv = (await this.rootRatchet.next(dhRecv))[0];
            this.recvRatchet = new SymmRatchet(sharedRecv);
            console.log('[Alice]\tRecv ratchet seed:', b64(sharedRecv));
        }

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

    async send(bob, msg) {
        const [key, iv] = await this.sendRatchet.next();
        const cipher = await encryptMessage(key, iv, msg);
        console.log('[Alice]\tSending ciphertext to Bob:', b64(cipher));
        bob.recv(cipher, this.DHratchet.publicKey);
    }

    async recv(cipher, bobPublicKey) {
        await this.dhRatchet(bobPublicKey);
        const [key, iv] = await this.recvRatchet.next();
        const decrypted = await decryptMessage(key, iv, cipher);
        console.log('[Alice]\tDecrypted message:', decrypted);
    }
}