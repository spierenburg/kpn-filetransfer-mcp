import { describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import {
  decodeKey,
  decryptBlob,
  downloadPasswordHeader,
  encodeKey,
  encryptBlob,
  newKeyMaterial,
  uploadPasswordValue,
} from "./crypto";

// Mirrors the browser bundle's WebCrypto calls (HKDF deriveKey, AES-GCM with
// additionalData = Uint8Array(1)) so node:crypto is checked against a second path.
async function webCryptoEncrypt(plaintext: Buffer, material: Buffer): Promise<Buffer> {
  const subtle = globalThis.crypto.subtle;
  const base = await subtle.importKey("raw", material, "HKDF", false, ["deriveKey"]);
  const hkdf = (info: string) => ({ name: "HKDF", salt: new Uint8Array(8), info: new TextEncoder().encode(info), hash: "SHA-256" });
  const key = await subtle.deriveKey(hkdf("fileEncryptionKey"), base, { name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const ivKey = await subtle.deriveKey(hkdf("iv"), base, { name: "AES-GCM", length: 128 }, true, ["encrypt"]);
  const iv = new Uint8Array(await subtle.exportKey("raw", ivKey)).subarray(0, 12);
  const out = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: new Uint8Array(1), tagLength: 128 }, key, plaintext);
  return Buffer.from(out);
}

describe("blob crypto", () => {
  test("round-trips", () => {
    const data = randomBytes(5000);
    const material = newKeyMaterial(data);
    expect(decryptBlob(encryptBlob(data, material), material).equals(data)).toBe(true);
  });

  test("matches an independent WebCrypto implementation byte-for-byte", async () => {
    const data = randomBytes(3000);
    const material = newKeyMaterial(data);
    expect((await webCryptoEncrypt(data, material)).equals(encryptBlob(data, material))).toBe(true);
  });

  test("rejects tampered ciphertext", () => {
    const data = randomBytes(100);
    const material = newKeyMaterial(data);
    const ct = encryptBlob(data, material);
    ct[0] ^= 1;
    expect(() => decryptBlob(ct, material)).toThrow();
  });

  test("rejects wrong key", () => {
    const data = randomBytes(100);
    const ct = encryptBlob(data, newKeyMaterial(data));
    expect(() => decryptBlob(ct, newKeyMaterial(data))).toThrow();
  });
});

describe("key encoding", () => {
  test("32 bytes encodes to 44 chars with '.' padding and round-trips", () => {
    const material = randomBytes(32);
    const enc = encodeKey(material);
    expect(enc).toHaveLength(44);
    expect(enc.endsWith(".")).toBe(true);
    expect(enc).not.toContain("=");
    expect(decodeKey(enc).equals(material)).toBe(true);
  });
});

describe("password hash", () => {
  const id = "4bfa24d1-2334-4b82-805b-5f2843c6d2a0";
  const key = Buffer.alloc(32, 7);

  test("matches a hand-assembled preimage", () => {
    const pre = Buffer.concat([
      Buffer.from([0, 0, 1, 0]),
      key,
      Buffer.from([0, 0, 1, 0x20]),
      Buffer.from(id),
      Buffer.from([0, 0, 0, 56]),
      Buffer.from("hunter2"),
    ]);
    expect(downloadPasswordHeader(id, key, "hunter2")).toBe(createHash("sha256").update(pre).digest("hex"));
  });

  test("length field counts UTF-16 units, not UTF-8 bytes", () => {
    const pw = "pässword";
    const pre = Buffer.concat([
      Buffer.from([0, 0, 1, 0]),
      key,
      Buffer.from([0, 0, 1, 0x20]),
      Buffer.from(id),
      Buffer.from([0, 0, 0, 64]),
      Buffer.from(pw, "utf8"),
    ]);
    expect(downloadPasswordHeader(id, key, pw)).toBe(createHash("sha256").update(pre).digest("hex"));
  });

  test("upload value is a second SHA-256 of the first hash", () => {
    const first = Buffer.from(downloadPasswordHeader(id, key, "hunter2"), "hex");
    expect(uploadPasswordValue(id, key, "hunter2")).toBe(createHash("sha256").update(first).digest("hex"));
  });
});
