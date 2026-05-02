import { createLocalJWKSet, importPKCS8, jwtVerify, SignJWT } from "jose";
import type { JWTPayload } from "jose";
import { getActiveKid, getJWKS, getKeyPair } from "./cert";

export async function verifyBearerToken(
    req: Request,
    issuer: string,
): Promise<JWTPayload | Response> {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
        return Response.json({ error: "Missing or invalid Authorization header." }, { status: 401 });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
        return Response.json({ error: "Missing token." }, { status: 401 });
    }

    try {
        const { keys } = await getJWKS();
        const JWKS = createLocalJWKSet({ keys });
        const { payload } = await jwtVerify(token, JWKS, { algorithms: ["RS256"], issuer });
        return payload;
    } catch {
        return Response.json({ error: "Invalid or expired token." }, { status: 401 });
    }
}

export async function signUserToken(user: Record<string, unknown>, issuer: string): Promise<string> {
    const kid = getActiveKid();
    const { privateKeyPem } = getKeyPair(kid);
    const PRIVATE_KEY = await importPKCS8(privateKeyPem, "RS256");

    return new SignJWT({
        sub: user.id as string,
        email: user.email,
        email_verified: user.emailVerified,
        given_name: user.firstName ?? "",
        family_name: user.lastName ?? undefined,
        name: [user.firstName, user.lastName].filter(Boolean).join(" "),
        picture: user.profileImageURL ?? undefined,
    })
        .setProtectedHeader({ alg: "RS256", kid })
        .setIssuer(issuer)
        .setIssuedAt(Date.now())
        .setExpirationTime("1h")
        .sign(PRIVATE_KEY);
}

/** Generates a cryptographically secure random hex string. */
export function generateSecret(bytes = 32): string {
    return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

/** SHA-256 hashes a string (for refresh tokens). */
export async function hashSecret(value: string): Promise<string> {
    const data = new TextEncoder().encode(value);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

