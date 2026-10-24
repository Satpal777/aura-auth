import { createLocalJWKSet, importPKCS8, jwtVerify, SignJWT, type KeyLike } from "jose";
import type { JWTPayload } from "jose";
import { getActiveKid, getJWKS, getKeyPair } from "./cert";

/** Cached imported private key to avoid re-parsing PEM on every sign operation. */
let cachedPrivateKey: { kid: string; key: KeyLike } | null = null;

async function getSigningKey(): Promise<{ kid: string; key: KeyLike }> {
  const kid = getActiveKid();
  if (cachedPrivateKey?.kid === kid) return cachedPrivateKey;

  const { privateKeyPem } = getKeyPair(kid);
  const key = await importPKCS8(privateKeyPem, "RS256");
  cachedPrivateKey = { kid, key };
  return cachedPrivateKey;
}

export async function verifyBearerToken(
    req: Request,
    issuer: string,
    corsHeaders: Record<string, string>,
): Promise<JWTPayload | Response> {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
        return Response.json(
          { error: "Missing or invalid Authorization header." },
          { status: 401, headers: corsHeaders },
        );
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
        return Response.json(
          { error: "Missing token." },
          { status: 401, headers: corsHeaders },
        );
    }

    try {
        const { keys } = await getJWKS();
        const JWKS = createLocalJWKSet({ keys });
        const { payload } = await jwtVerify(token, JWKS, { algorithms: ["RS256"], issuer });
        return payload;
    } catch {
        return Response.json(
          { error: "Invalid or expired token." },
          { status: 401, headers: corsHeaders },
        );
    }
}

export async function signUserToken(user: Record<string, unknown>, issuer: string): Promise<string> {
    const { kid, key } = await getSigningKey();

    return new SignJWT({
        sub: user.id as string,
        email: user.email,
        email_verified: user.email_verified,
        given_name: user.first_name ?? "",
        family_name: user.last_name ?? undefined,
        name: [user.first_name, user.last_name].filter(Boolean).join(" "),
        picture: user.profile_image_url ?? undefined,
    })
        .setProtectedHeader({ alg: "RS256", kid })
        .setIssuer(issuer)
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(key);
}

/** Generates a cryptographically secure random hex string. */
export function generateSecret(bytes = 32): string {
    return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

/** SHA-256 hashes a string (for refresh tokens / client secrets). */
export async function hashSecret(value: string): Promise<string> {
    const data = new TextEncoder().encode(value);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}
