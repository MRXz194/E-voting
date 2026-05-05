// E-Voting Zero-Knowledge Crypto JS
// Implements ElGamal, RSA Blind Signature, and HMAC in Browser

const CryptoUtils = {
    // SHA-256 return hex string
    async sha256Hex(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    // SHA-256 return BigInt
    async sha256BigInt(message) {
        const hex = await this.sha256Hex(message);
        return BigInt('0x' + hex);
    },

    // Lũy thừa modulo an toàn (BigInt)
    modPow(base, exp, mod) {
        if (mod === 1n) return 0n;
        let result = 1n;
        base = base % mod;
        while (exp > 0n) {
            if (exp % 2n === 1n) result = (result * base) % mod;
            exp = exp / 2n;
            base = (base * base) % mod;
        }
        return result;
    },

    // Extended GCD (BigInt)
    extendedGCD(a, b) {
        if (a === 0n) return [b, 0n, 1n];
        let [g, x1, y1] = this.extendedGCD(b % a, a);
        let x = y1 - (b / a) * x1;
        let y = x1;
        return [g, x, y];
    },

    // Mod Inverse (BigInt)
    modInverse(a, m) {
        let [g, x, y] = this.extendedGCD(a % m, m);
        if (g !== 1n) throw new Error("Inverse doesn't exist");
        return (x % m + m) % m;
    },

    // Generate random BigInt within range
    getRandomBigInt(max) {
        // Simple random generator for demo purposes
        const hexDigits = max.toString(16).length;
        let result = max;
        while (result >= max || result <= 1n) {
            let hex = '';
            for (let i = 0; i < hexDigits; i++) {
                hex += Math.floor(Math.random() * 16).toString(16);
            }
            result = BigInt('0x' + hex);
        }
        return result;
    },

    // RSA Blind Signature Phase 1: Blind
    async blindToken(token, rsaN, rsaE) {
        const N = BigInt(rsaN);
        const e = BigInt(rsaE);
        const h = await this.sha256BigInt(token);
        const hMod = h % N;

        let r;
        while (true) {
            r = this.getRandomBigInt(N);
            if (this.extendedGCD(r, N)[0] === 1n) break;
        }

        const r_e = this.modPow(r, e, N);
        const blinded = (r_e * hMod) % N;
        return { blinded: blinded.toString(), r: r.toString() };
    },

    // RSA Blind Signature Phase 3: Unblind
    unblindSignature(blindSig, r, rsaN) {
        const N = BigInt(rsaN);
        const sig = BigInt(blindSig);
        const rBig = BigInt(r);
        const rInv = this.modInverse(rBig, N);
        const unblinded = (sig * rInv) % N;
        return unblinded.toString();
    },

    // ElGamal Encrypt 0 or 1
    elGamalEncrypt(voteBit, egP, egG, egY) {
        const p = BigInt(egP);
        const g = BigInt(egG);
        const y = BigInt(egY);
        const v = BigInt(voteBit);

        // encode m = g^v mod p
        const m = this.modPow(g, v, p);
        const k = this.getRandomBigInt(p - 2n);

        const c1 = this.modPow(g, k, p);
        let c2 = this.modPow(y, k, p);
        c2 = (m * c2) % p;

        return { c1: c1.toString(), c2: c2.toString() };
    },

    // HMAC SHA256 Web Crypto API
    async computeHMAC(token, credential, c1Json, c2Json) {
        const rawKey = `${token}:${credential}`;
        const keyBuffer = new TextEncoder().encode(rawKey);
        
        // Derive key using SHA-256 (like Python)
        const hashBuffer = await crypto.subtle.digest('SHA-256', keyBuffer);
        
        // Import raw bytes as HMAC key
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            hashBuffer,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        // Compute HMAC
        const payload = `${token}|${c1Json}|${c2Json}`;
        const payloadBuffer = new TextEncoder().encode(payload);
        const hmacBuffer = await crypto.subtle.sign('HMAC', cryptoKey, payloadBuffer);
        
        // Convert to Hex
        const hmacArray = Array.from(new Uint8Array(hmacBuffer));
        return hmacArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
};

window.CryptoUtils = CryptoUtils;
