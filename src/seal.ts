import crypto from "node:crypto";
import type { SealedSecret } from "./types.js";

export async function sealSecret(
  name: string,
  value: string,
  passphrase: string,
): Promise<SealedSecret> {
  validate(name, value, passphrase);
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = await deriveKey(passphrase, salt);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final(),
  ]);
  return {
    version: "0.1",
    name,
    kdf: "scrypt",
    cipher: "aes-256-gcm",
    salt: salt.toString("base64url"),
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    created_at: new Date().toISOString(),
  };
}

export async function openSecret(
  secret: SealedSecret,
  passphrase: string,
): Promise<string> {
  if (
    secret.version !== "0.1" ||
    secret.kdf !== "scrypt" ||
    secret.cipher !== "aes-256-gcm"
  ) {
    throw new Error("unsupported sealed secret format.");
  }
  const key = await deriveKey(
    passphrase,
    Buffer.from(secret.salt, "base64url"),
  );
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(secret.iv, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(secret.tag, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(secret.ciphertext, "base64url")),
    decipher.final(),
  ]);
  return plaintext.toString("utf8");
}

function validate(name: string, value: string, passphrase: string): void {
  if (!name.match(/^[A-Z0-9_][A-Z0-9_:-]*$/i))
    throw new Error("secret name must be identifier-like.");
  if (!value) throw new Error("secret value is required.");
  if (passphrase.length < 12)
    throw new Error("passphrase must be at least 12 characters.");
}

function deriveKey(passphrase: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(
      passphrase,
      salt,
      32,
      { N: 16384, r: 8, p: 1 },
      (error, key) => {
        if (error) reject(error);
        else resolve(key);
      },
    );
  });
}
