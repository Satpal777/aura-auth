import { readdirSync, readFileSync } from "fs";
import { join, resolve } from "path";
import { exportJWK, importSPKI } from "jose";

const CERT_DIR = resolve("./certs");

type KeyPair = {
  kid: string;
  publicKeyPem: string;
  privateKeyPem: string;
};

export function getKeyPair(kid: string): KeyPair {
  const publicKeyPem = readFileSync(
    join(CERT_DIR, `${kid}.public.pem`),
    "utf-8"
  );

  const privateKeyPem = readFileSync(
    join(CERT_DIR, `${kid}.private.pem`),
    "utf-8"
  );

  return { kid, publicKeyPem, privateKeyPem };
}

export function getActiveKid(): string {
  const files = readdirSync(CERT_DIR)
    .filter(f => f.endsWith(".private.pem"))
    .sort()
    .reverse();

  const latest = files[0];
  if (!latest) throw new Error("No keys found");

  const kid = latest.split(".")[0];
  if (!kid) throw new Error("Invalid key file name");
  return kid;
}

export async function getJWKS() {
  const files = readdirSync(CERT_DIR).filter(f =>
    f.endsWith(".public.pem")
  );

  const keys = [];

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

  return { keys };
}