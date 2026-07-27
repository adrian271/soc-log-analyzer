import { randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCb);
const KEY_LEN = 64;

/**
 * Hash a password with scrypt. Stored as `scrypt$<saltHex>$<keyHex>` so the
 * salt travels with the hash and we never need a second column.
 *
 * Plain JS (not TS) on purpose: `scripts/migrate.mjs` runs under bare node and
 * imports this same module, so there is exactly one hashing implementation.
 *
 * @param {string} password
 * @returns {Promise<string>}
 */
export async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = /** @type {Buffer} */ (await scrypt(password, salt, KEY_LEN));
  return `scrypt$${salt.toString("hex")}$${key.toString("hex")}`;
}

/**
 * Constant-time verification of a password against a stored hash.
 *
 * @param {string} password
 * @param {string} stored
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(password, stored) {
  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const salt = Buffer.from(parts[1], "hex");
  const expected = Buffer.from(parts[2], "hex");
  if (expected.length !== KEY_LEN) return false;
  const actual = /** @type {Buffer} */ (await scrypt(password, salt, KEY_LEN));
  return timingSafeEqual(actual, expected);
}
