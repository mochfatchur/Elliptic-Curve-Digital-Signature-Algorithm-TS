"use strict";
// import crypto from "crypto";
// import { createHash } from "crypto";
// type Curve = {
//     p: bigint;
//     a: bigint;
//     b: bigint;
//     G: Point;
//     n: bigint;
// };
// type Point = readonly [bigint, bigint];
// function modInverse(a: bigint, m: bigint): bigint {
//     let [old_r, r] = [a, m];
//     let [old_t, t] = [0n, 1n];
//     while (r !== 0n) {
//       const q = old_r / r;
//       [old_r, r] = [r, old_r - q * r];
//       [old_t, t] = [t, old_t - q * t];
//     }
//     if (old_r !== 1n) {
//       throw new Error(`${a} and ${m} are not coprime`);
//     }
//     return old_t >= 0n ? old_t : old_t + m;
// }
// function add(curve: Curve, p: Point, q: Point): Point {
//     const [px, py] = p;
//     const [qx, qy] = q;
//     if (px === qx && py === qy) {
//       return double(curve, p);
//     }
//     const s = ((qy - py) * modInverse(qx - px, curve.p)) % curve.p;
//     const x = (s * s - px - qx) % curve.p;
//     const y = (s * (px - x) - py) % curve.p;
//     return [x, y] as const;
// }
// function double(curve: Curve, p: Point): Point {
//     const [px, py] = p;
//     const s = ((3n * px * px + curve.a) * modInverse(2n * py, curve.p)) % curve.p;
//     const x = (s * s - 2n * px) % curve.p;
//     const y = (s * (px - x) - py) % curve.p;
//     return [x, y] as const;
// }
// function multiply(curve: Curve, p: Point, n: bigint): Point {
//     let result = [0n, 0n] as Point;
//     let addend = p;
//     while (n) {
//       if (n & 1n) {
//         result = add(curve, result, addend);
//       }
//       addend = double(curve, addend);
//       n >>= 1n;
//     }
//     return result;
// }
// function sign(curve: Curve, message: string, privateKey: bigint): Point {
//     const z = BigInt("0x" + Buffer.from(message, "utf8").toString("hex"));
//     const k = BigInt("0x" + crypto.randomBytes(32).toString("hex"));
//     const [x, y] = multiply(curve, curve.G, k);
//     const r = x % curve.n;
//     const s = ((z + r * privateKey) * modInverse(k, curve.n)) % curve.n;
//     return [r, s] as const;
// }
// function verify(curve: Curve, message: string, publicKey: Point, point: Point): boolean {
//     const z = BigInt("0x" + Buffer.from(message, "utf8").toString("hex"));
//     const [r, s] = point;
//     const w = modInverse(s, curve.n);
//     const u1 = (z * w) % curve.n;
//     const u2 = (r * w) % curve.n;
//     const X = add(curve, multiply(curve, curve.G, u1), multiply(curve, publicKey, u2));
//     return X[0] === r;
// }
