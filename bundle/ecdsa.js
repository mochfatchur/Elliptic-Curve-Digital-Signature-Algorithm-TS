"use strict";
// import crypto from "crypto";
// import { createHash } from "crypto";
// type Point = [bigint, bigint];
// interface Curve {
//   a: bigint;
//   b: bigint;
//   p: bigint;
//   G: Point;
//   n: bigint;
// }
// interface Signature {
//   r: bigint;
//   s: bigint;
// }
// const secp256k1: Curve = {
//     a: BigInt(0x0000000000000000000000000000000000000000000000000000000000000000),
//     b: BigInt(0x0000000000000000000000000000000000000000000000000000000000000007),
//     p: BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
//     G: [
//       BigInt("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
//       BigInt("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
//     ] as Point,
//     n: BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
// };
// function mod(n: bigint, m: bigint): bigint {
//     return ((n % m) + m) % m;
// }
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
