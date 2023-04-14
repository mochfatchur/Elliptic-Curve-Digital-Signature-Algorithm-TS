import { sha512 } from 'js-sha512';

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
function signing(message: string, publicKey: [bigint, bigint], privateKey: bigint): [bigint , bigint]{
  const messageInt = textToInt(message);
  const r = hashing(String(hashing(String(messageInt)) + messageInt)) % p;
  const R = applyDoubleAndAddMethod(base, r, a, d, p);
  const h = hashing(String(R[0] + publicKey[0] + messageInt)) % p;
  // % p
  const s = (r + h * privateKey);
  
  return [r,s];
}

// verification signature
function verify(message: string, r: bigint, sign: bigint, publicKey: [bigint, bigint]):boolean{

  // hashing
  const messageInt = textToInt(message);
  const R = applyDoubleAndAddMethod(base, r, a, d, p);
  const h = hashing(String(R[0] + publicKey[0] + messageInt)) % p;

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

// Signature Encoder and Decoder

function encodeSignature(r: string, s: string): Uint8Array {
  // Convert the signature values from hexadecimal to Uint8Array format
  const rBytes = hexToBytes(r);
  const sBytes = hexToBytes(s);

  // Calculate the total length of the signature in bytes
  const totalLength = 6 + rBytes.length + sBytes.length;

  // Allocate a new Uint8Array with the length of the signature
  const der = new Uint8Array(totalLength);

  // Encode the signature in DER format
  der[0] = 0x30; // sequence tag
  der[1] = totalLength - 2; // sequence length
  der[2] = 0x02; // integer tag for r
  der[3] = rBytes.length; // length of r
  der.set(rBytes, 4); // r value
  der[4 + rBytes.length] = 0x02; // integer tag for s
  der[5 + rBytes.length] = sBytes.length; // length of s
  der.set(sBytes, 6 + rBytes.length); // s value

  // Return the binary-encoded signature as a Uint8Array
  return der;
}

function decodeSignature(der: Uint8Array): { r: string, s: string } {
  // Check that the input is a valid DER signature
  if (der[0] !== 0x30 || der.length !== der[1] + 2) {
    throw new Error('Invalid DER signature');
  }

  // Extract the values of r and s from the DER signature
  const rStart = 4;
  const rLength = der[3];
  const rEnd = rStart + rLength;
  const sStart = rEnd + 2;
  const sLength = der[5 + rLength];
  const sEnd = sStart + sLength;
  const rBytes = der.slice(rStart, rEnd);
  const sBytes = der.slice(sStart, sEnd);
  const r = bytesToHex(rBytes);
  const s = bytesToHex(sBytes);

  // Return the decoded signature values
  return { r, s };
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
  return Array.prototype.map.call(bytes, x => ('00' + x.toString(16)).slice(-2)).join('');
}




console.log("----------- Testing Fungsional of ECDSA ----------------");

console.log("--- Message ---");
const message = "Hello World";
console.log("Message: ", message);

console.log("--- Key ---");
const privateKey: bigint = 47379675103498394144858916095175689n;
const publicKey: [bigint,bigint] = generatePublicKey(privateKey);
console.log("private key: ", privateKey);
console.log("public key: ", publicKey);

console.log("--- Signing ---");
const signature : [bigint , bigint] = signing(message, publicKey, privateKey);
console.log("Signature", signature);

console.log("--- Verification ---");
const message1 = "Hello World";
const r = signature[0];
const s = signature[1];
const valid = verify(message1, r, s, publicKey);

if (valid){
  console.log("signature benar");
}else{
  console.log("signature tidak benar");
}

console.log("-- bigInt toString hex --");
const rhex = signature[0].toString(16);
const shex = signature[1].toString(16)

console.log("r: ", rhex);
console.log("s: ", shex);

console.log("----------- Testing Fungsional of Signature Encoder ----------------");

// const r = '1e4c4e9684aa4b7e524e9d29c48cd8f11241d0740dc778dfe107dce7e8ec72f8';
// const s = '9b9d90c3bb2a1a41d52727d23c54fc8e7a407a4fc4cc4fc4a4f8a07c34b4eb2c';

const signatureEnc = encodeSignature(rhex, shex);
console.log(signatureEnc);

const decodedSignature = decodeSignature(signatureEnc);
console.log(decodedSignature);
