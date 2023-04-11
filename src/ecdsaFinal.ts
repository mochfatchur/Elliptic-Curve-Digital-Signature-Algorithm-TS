import { sha512 } from 'js-sha512';
import { randomBytes } from "crypto";

const p: bigint = 2n ** 255n - 19n;

const base: [bigint, bigint] = [
  15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  46316835694926478169428394003475163141307993866256225615783033603165251855960n,
];

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

// TESTING */62
// console.log(textToInt("Akulah"));
// console.log(findModInverse())
// TESTING */62



function applyDoubleAndAddMethod(P: [bigint, bigint], k: bigint, a: bigint, d: bigint, mod: bigint): [bigint, bigint] {
  let additionPoint: [bigint, bigint] = [P[0], P[1]];
  const kAsBinary: string = k.toString(2); // Convert k to binary
  
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


// ax^2 + y^2  = 1 + dx^2y^2
// ed25519
const a = BigInt(-1);
// const d = findPositiveModulus(-121665 * findModInverse(121666, p), p);
const d = findPositiveModulus(BigInt(-121665) * findModInverse(121666n, p)!, p);
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
const privateKey: bigint = 47379675103498394144858916095175689n;

console.log("===== TESTING applyDoubleAndAddMethod Part 1 =====");

console.log("private key: ",privateKey);
const publicKey = applyDoubleAndAddMethod(base, privateKey, a, d, p);
console.log("public key: ", publicKey);

const message = textToInt("Hello, world!");

// Function for hashing the message
function hashing(message: string): bigint {
  const hash = sha512(message);
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
console.log("message: ",message);
console.log("Signature (R, s)");
console.log("R: ",R);
console.log("s: ",s);

console.log("===== TESTING applyDoubleAndAddMethod Part 3 =====");

// -----------------------------------
// verify
const h1 = hashing(String(R[0] + publicKey[0] + message)) % p;

const P1 = applyDoubleAndAddMethod(base, s, a, d, p);

const P2 = pointAddition(R, applyDoubleAndAddMethod(publicKey, h1, a, d, p), a, d, p);

console.log("----------------------");
console.log("Verification:");
console.log("P1: ",P1);
console.log("P2: ",P2);
console.log("----------------------");
console.log("result");
if (P1[0] == P2[0] && P1[1] == P2[1]) {
  console.log("The Signature is valid");
} else {
  console.log("The Signature violation detected!");
}
// ----------------------------------