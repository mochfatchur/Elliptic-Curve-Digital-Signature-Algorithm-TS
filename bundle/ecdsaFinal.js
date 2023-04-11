"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const js_sha512_1 = require("js-sha512");
const p = 2n ** 255n - 19n;
const base = [
    15112221349535400772501151409588531511454012693041857206046113283949847762202n,
    46316835694926478169428394003475163141307993866256225615783033603165251855960n,
];
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
        // a = (a + m * BigInt(Math.abs(Number(a)) / Number(m)) + m) % m;
        a = (a % m + m) % m; // ensure that a is smaller than m
        // a = (a + m * BigInt(Math.abs(Number(a)) / Number(m)) + m) % m;
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
// TESTING */62
// console.log(textToInt("Akulah"));
// console.log(findModInverse())
// TESTING */62
function applyDoubleAndAddMethod(P, k, a, d, mod) {
    let additionPoint = [P[0], P[1]];
    const kAsBinary = k.toString(2); // Convert k to binary
    // TESTING
    console.log("k", k);
    console.log("kAsBinary", kAsBinary);
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
// ax^2 + y^2  = 1 + dx^2y^2
// ed25519
const a = BigInt(-1);
// const d = findPositiveModulus(-121665 * findModInverse(121666, p), p);
const d = findPositiveModulus(BigInt(-121665) * findModInverse(121666n, p), p);
console.log("===== TESTING findPositiveModulus =====");
console.log("a : ", a);
console.log("d : ", d);
console.log("===== TESTING findModInverse =====");
console.log("Hasil:", findModInverse(121666n, p));
// console.log("curve: ",a,"x^2 + y^2 = 1 + ",d,"x^2 y^2");
const x0 = base[0];
const y0 = base[1];
console.log("----------------------");
console.log("Key Generation: ");
// const privateKey = 47379675103498394144858916095175689;
// 779086087640336534911165206022228115974270 //32 byte secret key
// const privateKey = random.int(0, 2**256); //32 byte secret key
// const privateKey = BigInt(random.int(0, 2**256));
// const privateKey: bigint = BigInt("0x" + randomBytes(32).toString("hex"));
const privateKey = 47379675103498394144858916095175689n;
console.log("===== TESTING applyDoubleAndAddMethod Part 1 =====");
console.log("private key: ", privateKey);
const publicKey = applyDoubleAndAddMethod(base, privateKey, a, d, p);
console.log("public key: ", publicKey);
const message = textToInt("Hello, world!");
// Function for hashing the message
function hashing(message) {
    const hash = (0, js_sha512_1.sha512)(message);
    const bigIntHash = BigInt('0x' + hash);
    return bigIntHash;
}
// ---------------------------------------
// sign
console.log("===== TESTING applyDoubleAndAddMethod Part 2 =====");
const r = hashing(String(hashing(String(message)) + message)) % p;
const R = applyDoubleAndAddMethod(base, r, a, d, p);
const h = hashing(String(R[0] + publicKey[0] + message)) % p;
// % p
const s = (r + h * privateKey);
// testing
console.log("===== TESTING Hashing =====");
console.log("hashing:", hashing(String(message)));
console.log("r:", r);
console.log("h:", h);
// masih ada beda di R
// console.log("base:",base);
// console.log("r:",r);
// console.log("a:",a);
// console.log("d:",d);
// console.log("p:",p);
console.log("----------------------");
console.log("Signing:");
console.log("message: ", message);
console.log("Signature (R, s)");
console.log("R: ", R);
console.log("s: ", s);
console.log("===== TESTING applyDoubleAndAddMethod Part 3 =====");
// -----------------------------------
// verify
const h1 = hashing(String(R[0] + publicKey[0] + message)) % p;
const P1 = applyDoubleAndAddMethod(base, s, a, d, p);
const P2 = pointAddition(R, applyDoubleAndAddMethod(publicKey, h1, a, d, p), a, d, p);
console.log("----------------------");
console.log("Verification:");
console.log("P1: ", P1);
console.log("P2: ", P2);
console.log("----------------------");
console.log("result");
if (P1[0] == P2[0] && P1[1] == P2[1]) {
    console.log("The Signature is valid");
}
else {
    console.log("The Signature violation detected!");
}
// ----------------------------------
