import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";

const SALT = Buffer.alloc(8);
const AAD = Buffer.alloc(1);
const TAG_LEN = 16;

export const CHUNK_SIZE = 16 * 1024 * 1024;

export type KeyMaterial = Buffer;

const sha256 = (...parts: Buffer[]): Buffer => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};

export function encodeKey(material: Buffer): string {
  const b64 = material.toString("base64url");
  return b64 + ".".repeat((4 - (b64.length % 4)) % 4);
}

export function decodeKey(encoded: string): Buffer {
  return Buffer.from(encoded.replace(/\./g, "="), "base64url");
}

export function newKeyMaterial(plaintext: Buffer): KeyMaterial {
  return sha256(sha256(plaintext), sha256(randomBytes(16)));
}

function derive(material: Buffer): { key: Buffer; iv: Buffer } {
  const key = Buffer.from(hkdfSync("sha256", material, SALT, "fileEncryptionKey", 32));
  const iv = Buffer.from(hkdfSync("sha256", material, SALT, "iv", 12));
  return { key, iv };
}

export function encryptBlob(plaintext: Buffer, material: KeyMaterial): Buffer {
  const { key, iv } = derive(material);
  const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_LEN });
  cipher.setAAD(AAD);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

export function decryptBlob(ciphertext: Buffer, material: KeyMaterial): Buffer {
  if (ciphertext.length < TAG_LEN) throw new Error("ciphertext shorter than GCM tag");
  const { key, iv } = derive(material);
  const decipher = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_LEN });
  decipher.setAAD(AAD);
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - TAG_LEN));
  return Buffer.concat([decipher.update(ciphertext.subarray(0, ciphertext.length - TAG_LEN)), decipher.final()]);
}

const be32 = (n: number): Buffer => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
};

// Length field counts UTF-16 code units (JS String.length), not UTF-8 bytes; the
// bundle does the same, so non-ASCII passwords only authenticate if we match it.
function passwordHash(transferId: string, manifestKey: Buffer, password: string): Buffer {
  return sha256(
    be32(256),
    manifestKey,
    be32(288),
    Buffer.from(transferId, "utf8"),
    be32(8 * password.length),
    Buffer.from(password, "utf8"),
  );
}

/** Value for the `Password` header on download. */
export function downloadPasswordHeader(transferId: string, manifestKey: Buffer, password: string): string {
  return passwordHash(transferId, manifestKey, password).toString("hex");
}

/**
 * Value for POST /api/v1/upload/password/. UNVERIFIED: assumes the bundle's
 * hashArrayBufferToHex is hex(SHA-256(firstHash)); that helper was not read.
 */
export function uploadPasswordValue(transferId: string, manifestKey: Buffer, password: string): string {
  return sha256(passwordHash(transferId, manifestKey, password)).toString("hex");
}
