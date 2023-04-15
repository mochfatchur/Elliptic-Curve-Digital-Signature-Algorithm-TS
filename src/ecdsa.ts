import { sha512 } from 'js-sha512';
import { encodeSignature, decodeSignature, toHexSignature } from './signatureEncoderDecoder';


// ============= ECDSA =============

// curve : ax^2 + y^2  = 1 + dx^2y^2
// ed25519

const base: [bigint, bigint] = [
  15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  46316835694926478169428394003475163141307993866256225615783033603165251855960n,
];
const p: bigint = 2n ** 255n - 19n;
const a = BigInt(-1);
const d = findPositiveModulus(BigInt(-121665) * findModInverse(121666n, p)!, p);



function findPositiveModulus(a: bigint, p: bigint): bigint {
  if (a < 0n) {
    a = (a + p * BigInt(Math.floor(Math.abs(Number(a)) / Number(p))) + p) % p;
  }
  return a;
}

function textToInt(text: string): bigint {
  const encodedText: Uint8Array = new TextEncoder().encode(text);
  const hexText: string = Array.prototype.map
    .call(encodedText, (x: number) => ('00' + x.toString(16)).slice(-2))
    .join('');
  const intText: bigint = BigInt('0x' + hexText);
  return intText;
}

function gcd(a: bigint, b: bigint): bigint {
  while (a !== 0n) {
    [a, b] = [b % a, a];
  }
  return b;
}

function findModInverse(a: bigint, m: bigint): bigint | null {
  if (a < 0n) {
    a = (a % m + m) % m; // ensure that a is smaller than m
    a = (a + m * BigInt(Math.floor(Math.abs(Number(a)) / Number(m))) + m) % m;
  }
  // no mod inverse if a & m aren't relatively prime
  if (gcd(a, m) !== 1n) {
    return null;
  }
  // Calculate using the Extended Euclidean Algorithm:
  let u1: bigint = 1n,
    u2: bigint = 0n,
    u3: bigint = a,
    v1: bigint = 0n,
    v2: bigint = 1n,
    v3: bigint = m;

  while (v3 !== 0n) {
    const q: bigint = u3 / v3;
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


function applyDoubleAndAddMethod(P: [bigint, bigint], k: bigint, a: bigint, d: bigint, mod: bigint): [bigint, bigint] {
  let additionPoint: [bigint, bigint] = [P[0], P[1]];
  const kAsBinary: string = k.toString(2); // Convert k to binary
  
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

function pointAddition(P: [bigint, bigint], Q: [bigint, bigint], a: bigint, d: bigint, mod: bigint): [bigint, bigint] {
  const x1: bigint = P[0];
  const y1: bigint = P[1];
  const x2: bigint = Q[0];
  const y2: bigint = Q[1];

  const u: bigint = 1n + d * x1 * x2 * y1 * y2;
  const v: bigint = 1n - d * x1 * x2 * y1 * y2;
  const uInverse: bigint | null = findModInverse(u, mod);
  const vInverse: bigint | null = findModInverse(v, mod);

  if (uInverse === null || vInverse === null) {
    throw new Error("Cannot calculate point addition: invalid input");
  }

  const x3: bigint = ((x1 * y2 + y1 * x2) % mod) * uInverse % mod;
  const y3: bigint = ((y1 * y2 - a * x1 * x2) % mod) * vInverse % mod;

  return [x3, y3];
}


// hashing the message
function hashing(message: string): bigint {
  const hash = sha512(message);
  const bigIntHash = BigInt('0x' + hash);
  return bigIntHash;
}

// generate public key
function generatePublicKey(privateKey: bigint): [bigint, bigint]{
  const publicKey = applyDoubleAndAddMethod(base, privateKey, a, d, p);
  return publicKey;
}


// generate signature
function signing(message: string, publicKey: [bigint, bigint], privateKey: bigint): { r: bigint , s: bigint } {
  const messageInt = textToInt(message);
  const r = hashing(String(hashing(String(messageInt)) + messageInt)) % p;
  const R = applyDoubleAndAddMethod(base, r, a, d, p);
  const h = hashing(String(R[0] + publicKey[0] + messageInt)) % p; // menggunakan teknik compression
  // const h = hashing(String(R[0] + publicKey[0] + publicKey[1] + messageInt)) % p;
  // % p
  const s = (r + h * privateKey);
  
  return { r,s };
}

// verification signature
function verify(message: string, r: bigint, sign: bigint, publicKey: [bigint, bigint]):boolean{

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
function compressPublicKey(publicKey: [bigint, bigint]): Uint8Array {
  const xBytes = publicKey[0].toString(16).padStart(64, '0');
  const yBit = publicKey[1] % 2n === 0n ? 0x02 : 0x03;
  return new Uint8Array([yBit, ...hexToBytes(xBytes)]);
}

function decompressPublicKey(compressedKey: Uint8Array): [bigint, bigint] {
  const xHex = bytesToHex(compressedKey.slice(1));
  const x = BigInt('0x' + xHex);
  const y = getYCoordinate(x, compressedKey[0] === 0x02 ? 0n : 1n);
  return [x, y];
}

function getYCoordinate(x: bigint, yBit: bigint): bigint {
  const p: bigint = 2n ** 255n - 19n;
  const a: bigint = BigInt(-1);
  const d: bigint = findPositiveModulus(BigInt(-121665) * findModInverse(121666n, p)!, p);
  const numerator = 1n + d * x * x;
  const denominator = 1n - a * x * x;
  const ySquared = numerator * findModInverse(denominator, p)!;
  const y = modPow(ySquared, (p + 3n) / 8n, p);
  if ((y % 2n) === yBit) {
    return y;
  } else {
    return p - y;
  }
}


// ============= Utils =============
function bigintToHex(num: bigint): string {
  const hex = num.toString(16).toUpperCase();
  return hex;
}

function hexToBigint(hex: string): bigint {
  const num = BigInt(`0x${hex}`);
  return num;
}

function hexToBytes(hex: string): Uint8Array {
  const len = hex.length / 2;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; ++i) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}


function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => {
    const hex = byte.toString(16);
    return hex.length === 1 ? '0' + hex : hex;
  }).join('');
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n;

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
const privateKey: bigint = 47379675103498394144858916095175689n;
const publicKey: [bigint,bigint] = generatePublicKey(privateKey);
console.log("private key: ", privateKey);
console.log("public key: ", publicKey);

console.log("\n--- Signing ---\n");
const signature  = signing(message, publicKey, privateKey);
console.log("Signature", signature);

console.log("\n--- Verification ---\n");
const message1 = "Hello World";
const r = signature.r;
const s = signature.s;
const valid = verify(message1, r, s, publicKey);

if (valid){
  console.log("signature benar");
}else{
  console.log("signature tidak benar");
}

console.log("\n--- Kompresi ---\n");
console.log("-- bigInt toString hex --\n");

const [rhex, shex] = toHexSignature([signature.r,signature.s]);
console.log("r (hex):", rhex);
console.log("s (hex):", shex);

console.log("\n----------- Testing Fungsional of Signature Encoder ----------------\n");

// const signatureEnc = encodeSignature(rhex, shex);
const signatureEnc = encodeSignature(rhex, shex);
console.log("\nSignature Final: ",signatureEnc);


console.log("\n----------- Testing Fungsional of Signature Decoder ----------------\n");
const decodedSignature = decodeSignature(signatureEnc);
console.log(decodedSignature);


console.log("\nApakah signature r sama dengan semula?");
if (signature.r == decodedSignature.r){
  console.log("benar");
}else{
  console.log("nggak");
}

console.log("\nApakah signature s sama dengan semula?");
if (signature.s == decodedSignature.s){
  console.log("benar");
}else{
  console.log("nggak");
}



