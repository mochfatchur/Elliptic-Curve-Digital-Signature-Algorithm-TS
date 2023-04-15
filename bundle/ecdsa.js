"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const js_sha512_1 = require("js-sha512");
const signatureEncoderDecoder_1 = require("./signatureEncoderDecoder");
// ============= ECDSA =============
// curve : ax^2 + y^2  = 1 + dx^2y^2
// ed25519
const base = [
    15112221349535400772501151409588531511454012693041857206046113283949847762202n,
    46316835694926478169428394003475163141307993866256225615783033603165251855960n,
];
const p = 2n ** 255n - 19n;
const a = BigInt(-1);
const d = findPositiveModulus(BigInt(-121665) * findModInverse(121666n, p), p);
function findPositiveModulus(a, p) {
    if (a < 0n) {
        a = (a + p * BigInt(Math.floor(Math.abs(Number(a)) / Number(p))) + p) % p;
    }
    return a;
}
function textToInt(text) {
    const encodedText = new TextEncoder().encode(text);
    const hexText = Array.prototype.map
        .call(encodedText, (x) => ('00' + x.toString(16)).slice(-2))
        .join('');
    const intText = BigInt('0x' + hexText);
    return intText;
}
function gcd(a, b) {
    while (a !== 0n) {
        [a, b] = [b % a, a];
    }
    return b;
}
function findModInverse(a, m) {
    if (a < 0n) {
        a = (a % m + m) % m; // ensure that a is smaller than m
        a = (a + m * BigInt(Math.floor(Math.abs(Number(a)) / Number(m))) + m) % m;
    }
    // no mod inverse if a & m aren't relatively prime
    if (gcd(a, m) !== 1n) {
        return null;
    }
    // Calculate using the Extended Euclidean Algorithm:
    let u1 = 1n, u2 = 0n, u3 = a, v1 = 0n, v2 = 1n, v3 = m;
    while (v3 !== 0n) {
        const q = u3 / v3;
        [v1, v2, v3, u1, u2, u3] = [
            u1 - q * v1,
            u2 - q * v2,
            u3 - q * v3,
            v1,
            v2,
            v3,
        ];
    }
    return findPositiveModulus(u1, m);
}
function applyDoubleAndAddMethod(P, k, a, d, mod) {
    let additionPoint = [P[0], P[1]];
    const kAsBinary = k.toString(2); // Convert k to binary
    for (let i = 1; i < kAsBinary.length; i++) {
        const currentBit = kAsBinary.charAt(i);
        // always apply doubling
        additionPoint = pointAddition(additionPoint, additionPoint, a, d, mod);
        if (currentBit === '1') {
            // add base point
            additionPoint = pointAddition(additionPoint, P, a, d, mod);
        }
    }
    return additionPoint;
}
function pointAddition(P, Q, a, d, mod) {
    const x1 = P[0];
    const y1 = P[1];
    const x2 = Q[0];
    const y2 = Q[1];
    const u = 1n + d * x1 * x2 * y1 * y2;
    const v = 1n - d * x1 * x2 * y1 * y2;
    const uInverse = findModInverse(u, mod);
    const vInverse = findModInverse(v, mod);
    if (uInverse === null || vInverse === null) {
        throw new Error("Cannot calculate point addition: invalid input");
    }
    const x3 = ((x1 * y2 + y1 * x2) % mod) * uInverse % mod;
    const y3 = ((y1 * y2 - a * x1 * x2) % mod) * vInverse % mod;
    return [x3, y3];
}
// hashing the message
function hashing(message) {
    const hash = (0, js_sha512_1.sha512)(message);
    const bigIntHash = BigInt('0x' + hash);
    return bigIntHash;
}
// generate public key
function generatePublicKey(privateKey) {
    const publicKey = applyDoubleAndAddMethod(base, privateKey, a, d, p);
    return publicKey;
}
// generate signature
function signing(message, publicKey, privateKey) {
    const messageInt = textToInt(message);
    const r = hashing(String(hashing(String(messageInt)) + messageInt)) % p;
    const R = applyDoubleAndAddMethod(base, r, a, d, p);
    const h = hashing(String(R[0] + publicKey[0] + messageInt)) % p; // menggunakan teknik compression
    // const h = hashing(String(R[0] + publicKey[0] + publicKey[1] + messageInt)) % p;
    // % p
    const s = (r + h * privateKey);
    return { r, s };
}
// verification signature
function verify(message, r, sign, publicKey) {
    // hashing
    const messageInt = textToInt(message);
    const R = applyDoubleAndAddMethod(base, r, a, d, p);
    const h = hashing(String(R[0] + publicKey[0] + messageInt)) % p; // menggunakan teknik compression
    // const h = hashing(String(R[0] + publicKey[0] + publicKey[1] + messageInt)) % p;
    // verify
    const P1 = applyDoubleAndAddMethod(base, sign, a, d, p);
    const P2 = pointAddition(R, applyDoubleAndAddMethod(publicKey, h, a, d, p), a, d, p);
    // checking
    if (P1[0] == P2[0] && P1[1] == P2[1]) {
        // Signature is valid
        return true;
    }
    // Signature violation detected
    return false;
}
// public key compressor
function compressPublicKey(publicKey) {
    const xBytes = publicKey[0].toString(16).padStart(64, '0');
    const yBit = publicKey[1] % 2n === 0n ? 0x02 : 0x03;
    return new Uint8Array([yBit, ...hexToBytes(xBytes)]);
}
function decompressPublicKey(compressedKey) {
    const xHex = bytesToHex(compressedKey.slice(1));
    const x = BigInt('0x' + xHex);
    const y = getYCoordinate(x, compressedKey[0] === 0x02 ? 0n : 1n);
    return [x, y];
}
function getYCoordinate(x, yBit) {
    const p = 2n ** 255n - 19n;
    const a = BigInt(-1);
    const d = findPositiveModulus(BigInt(-121665) * findModInverse(121666n, p), p);
    const numerator = 1n + d * x * x;
    const denominator = 1n - a * x * x;
    const ySquared = numerator * findModInverse(denominator, p);
    const y = modPow(ySquared, (p + 3n) / 8n, p);
    if ((y % 2n) === yBit) {
        return y;
    }
    else {
        return p - y;
    }
}
// ============= Utils =============
function bigintToHex(num) {
    const hex = num.toString(16).toUpperCase();
    return hex;
}
function hexToBigint(hex) {
    const num = BigInt(`0x${hex}`);
    return num;
}
function hexToBytes(hex) {
    const len = hex.length / 2;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; ++i) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
function bytesToHex(bytes) {
    return Array.from(bytes, (byte) => {
        const hex = byte.toString(16);
        return hex.length === 1 ? '0' + hex : hex;
    }).join('');
}
function modPow(base, exponent, modulus) {
    if (modulus === 1n)
        return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
        if (exponent % 2n === 1n) {
            result = (result * base) % modulus;
        }
        exponent = exponent >> 1n;
        base = (base * base) % modulus;
    }
    return result;
}
// console.log("----------- Testing Fungsional of ECDSA ----------------");
console.log("--- Message ---");
const message = "Hello World";
console.log("Message: ", message);
console.log("--- Key ---");
const privateKey = 47379675103498394144858916095175689n;
const publicKey = generatePublicKey(privateKey);
console.log("private key: ", privateKey);
console.log("public key: ", publicKey);
console.log("\n--- Signing ---\n");
const signature = signing(message, publicKey, privateKey);
console.log("Signature", signature);
console.log("\n--- Verification ---\n");
const message1 = "Hello World";
const r = signature.r;
const s = signature.s;
const valid = verify(message1, r, s, publicKey);
if (valid) {
    console.log("signature benar");
}
else {
    console.log("signature tidak benar");
}
console.log("\n--- Kompresi ---\n");
console.log("-- bigInt toString hex --\n");
const [rhex, shex] = (0, signatureEncoderDecoder_1.toHexSignature)([signature.r, signature.s]);
console.log("r (hex):", rhex);
console.log("s (hex):", shex);
console.log("\n----------- Testing Fungsional of Signature Encoder ----------------\n");
// const signatureEnc = encodeSignature(rhex, shex);
const signatureEnc = (0, signatureEncoderDecoder_1.encodeSignature)(rhex, shex);
console.log("\nSignature Final: ", signatureEnc);
console.log("\n----------- Testing Fungsional of Signature Decoder ----------------\n");
const decodedSignature = (0, signatureEncoderDecoder_1.decodeSignature)(signatureEnc);
console.log(decodedSignature);
console.log("\nApakah signature r sama dengan semula?");
if (signature.r == decodedSignature.r) {
    console.log("benar");
}
else {
    console.log("nggak");
}
console.log("\nApakah signature s sama dengan semula?");
if (signature.s == decodedSignature.s) {
    console.log("benar");
}
else {
    console.log("nggak");
}
