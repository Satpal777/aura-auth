import { readdirSync, readFileSync } from "fs";
import { join, resolve } from "path";
import { exportJWK, importSPKI, type JWK } from "jose";
import { logger } from "./logger";

const CERT_DIR = resolve("./certs");

type KeyPair = {
  kid: string;
  publicKeyPem: string;
  privateKeyPem: string;
};

/** In-memory cache for key pairs to avoid re-reading from disk on every request. */
const keyPairCache = new Map<string, KeyPair>();

export function getKeyPair(kid: string): KeyPair {
  const cached = keyPairCache.get(kid);
  if (cached) return cached;

  const publicKeyPem = readFileSync(
    join(CERT_DIR, `${kid}.public.pem`),
    "utf-8"
  );

  const privateKeyPem = readFileSync(
    join(CERT_DIR, `${kid}.private.pem`),
    "utf-8"
  );

  const pair: KeyPair = { kid, publicKeyPem, privateKeyPem };
  keyPairCache.set(kid, pair);
  return pair;
}

let cachedActiveKid: string | null = null;

export function getActiveKid(): string {
  if (cachedActiveKid) return cachedActiveKid;

  const files = readdirSync(CERT_DIR)
    .filter(f => f.endsWith(".private.pem"))
    .sort()
    .reverse();

  const latest = files[0];
  if (!latest) throw new Error("No signing keys found in " + CERT_DIR);

  const kid = latest.split(".")[0];
  if (!kid) throw new Error("Invalid key file name: " + latest);

  cachedActiveKid = kid;
  logger.info("Active signing key loaded", { kid });
  return kid;
}

/** Cached JWKS to avoid re-importing + re-exporting on every request. */
let cachedJWKS: { keys: JWK[] } | null = null;

export async function getJWKS(): Promise<{ keys: JWK[] }> {
  if (cachedJWKS) return cachedJWKS;

  const files = readdirSync(CERT_DIR).filter(f =>
    f.endsWith(".public.pem")
  );

  const keys: JWK[] = [];

  for (const file of files) {
    const kid = file.split(".")[0];
    if (!kid) continue;

    const { publicKeyPem } = getKeyPair(kid);

    const key = await importSPKI(publicKeyPem, "RS256");
    const jwk = await exportJWK(key);

    keys.push({
      ...jwk,
      use: "sig",
      alg: "RS256",
      kid,
    });
  }

  cachedJWKS = { keys };
  logger.info("JWKS cache populated", { keyCount: keys.length });
  return cachedJWKS;
}

/**
 * Invalidate all caches. Call after key rotation.
 */
export function invalidateKeyCache(): void {
  keyPairCache.clear();
  cachedActiveKid = null;
  cachedJWKS = null;
  logger.info("Key caches invalidated");
}
