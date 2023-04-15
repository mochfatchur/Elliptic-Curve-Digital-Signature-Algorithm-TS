"use strict";
// Catatan : Kurva ed25519 memiliki panjang bytes signature yang fix length yaitu 32 bytes
// jadi kalo mau kompress signature tinggal tambahkan saja
Object.defineProperty(exports, "__esModule", { value: true });
exports.decodeSignature = exports.encodeSignature = exports.toHexSignature = void 0;
function toHexSignature(signature) {
    const r = signature[0].toString(16).padStart(64, '0');
    const s = signature[1].toString(16).padStart(64, '0');
    return [r, s];
}
exports.toHexSignature = toHexSignature;
function encodeSignature(r, s) {
    return r + s;
}
exports.encodeSignature = encodeSignature;
function decodeSignature(signature) {
    const rHex = signature.substring(0, 64);
    const sHex = signature.substring(64);
    const r = BigInt('0x' + rHex);
    const s = BigInt('0x' + sHex);
    return { r, s };
}
exports.decodeSignature = decodeSignature;
const signature = '1a7fcd04640627a071a4afbb92d4b5f50e47effbcc756c569520798970ee5e9e4652c414207d2612030002acb1efef706dcf6790eae5ce9a518bfeaaba5098ed4bf706641c2e9a3ed236a658b3c72';
const { r, s } = decodeSignature(signature);
console.log(`r: ${r.toString()}`);
console.log(`s: ${s.toString()}`);
