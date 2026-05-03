import { getJWKS } from "./utils/cert";
import authPage from "./../public/auth.html";
import signupPage from "./../public/singup.html";
import dashboardPage from "./../public/dashboard.html";
import indexPage from "./../public/index.html";
import { Database } from "./db/db";
import { generateSecret, hashSecret, signUserToken, verifyBearerToken } from "./utils/auth";

/**
 * Converts a JS string array to a PostgreSQL array literal: {"val1","val2"}
 * Required because Bun's SQL client does not auto-convert JS arrays.
 */
function toPostgresArray(arr: string[]): string {
    return '{' + arr.map(s => '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"').join(',') + '}';
}

const corsHeaders: Record<string, string> = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "*",
};

export const createServer = async () => {
    const pg = await Database.getInstance();
    console.log("latest version")
    const server = Bun.serve({
        development: true,
        port: 3000,

        fetch(req, server) {
            console.log("start of fetch")
            const url = new URL(req.url);
            const origin = req.headers.get("Origin") ?? "no-origin";
            console.log(`[CORS] ${req.method} ${url.pathname} | Origin: ${origin}`);

            if (req.method === "OPTIONS") {
                console.log(`[CORS] ↳ Preflight 204 for ${url.pathname}`);
                return new Response(null, { status: 204, headers: corsHeaders });
            }
            console.log(`[CORS] ↳ No route matched ${url.pathname} → 404`);
            return new Response("Not found.", { status: 404, headers: corsHeaders });
        },

        routes: {

            "/": indexPage,

            "/assets/*": async (req) => {
                const url = new URL(req.url);
                const filePath = `${import.meta.dir}/../public${url.pathname}`;
                const file = Bun.file(filePath);
                if (!(await file.exists())) {
                    return new Response("Not found.", { status: 404, headers: corsHeaders });
                }
                return new Response(file, { headers: corsHeaders });
            },

            "/.well-known/openid-configuration": _ => {
                console.log("Serving OpenID configuration");
                const issuer: string = process.env.ISSUER_URL ?? server.url.origin;
                return Response.json({
                    issuer,
                    authorization_endpoint: `${issuer}/o/authorize`,
                    token_endpoint: `${issuer}/o/token`,
                    userinfo_endpoint: `${issuer}/o/userinfo`,
                    jwks_uri: `${issuer}/.well-known/jwks.json`,
                }, { headers: corsHeaders });
            },

            "/.well-known/jwks.json": async _ => {
                const { keys } = await getJWKS();
                return Response.json({ keys }, { headers: corsHeaders });
            },

            "/o/authenticate": authPage,
            "/o/signup": signupPage,
            "/dashboard": dashboardPage,

            "/o/authenticate/sign-in": async (req) => {
                if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
                const { email, password } = await req.json() as any;
                if (!email || !password) {
                    return Response.json({ error: "Email and password are required." }, { status: 400, headers: corsHeaders });
                }

                const [user] = await pg`SELECT * FROM users WHERE email = ${email} LIMIT 1`;
                if (!user?.password) {
                    return Response.json({ error: "Invalid email or password." }, { status: 401, headers: corsHeaders });
                }

                const isMatch = await Bun.password.verify(password, user.password);
                if (!isMatch) {
                    return Response.json({ error: "Invalid email or password." }, { status: 401, headers: corsHeaders });
                }

                const token = await signUserToken(user, process.env.ISSUER_URL ?? server.url.origin);
                return Response.json({ token }, { status: 200, headers: corsHeaders });
            },

            "/o/authenticate/sign-up": async (req) => {
                if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
                const { firstName, lastName, email, password } = await req.json() as any;
                console.log("received", firstName, lastName, email, password);
                if (!email || !password || !firstName) {
                    return Response.json({ error: "Email, password, and first name are required." }, { status: 400, headers: corsHeaders });
                }

                console.log(firstName, lastName, email, password);
                const [existing] = await pg`SELECT id FROM users WHERE email = ${email} LIMIT 1`;
                if (existing) {
                    return Response.json({ error: "Email is already in use." }, { status: 409, headers: corsHeaders });
                }

                console.log("existing: ", existing);

                const hashedPassword = await Bun.password.hash(password);
                const [created] = await pg`
                    INSERT INTO users (first_name, last_name, email, password)
                    VALUES (${firstName}, ${lastName}, ${email}, ${hashedPassword})
                    RETURNING id
                `;

                console.log(created);

                if (!created?.id) {
                    return Response.json({ error: "Failed to create user." }, { status: 500, headers: corsHeaders });
                }

                return Response.json({ message: "Sign up successful." }, { status: 201, headers: corsHeaders });
            },

            "/o/userinfo": async (req) => {
                if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
                const claims = await verifyBearerToken(req, process.env.ISSUER_URL ?? server.url.origin);
                if (claims instanceof Response) return claims;

                const [user] = await pg`SELECT id FROM users WHERE id = ${claims.sub} LIMIT 1`;
                if (!user) {
                    return Response.json({ error: "User not found." }, { status: 404, headers: corsHeaders });
                }

                return Response.json({
                    sub: claims.sub,
                    email: claims.email,
                    email_verified: claims.email_verified,
                    given_name: claims.given_name,
                    family_name: claims.family_name,
                    name: claims.name,
                    picture: claims.picture,
                }, { headers: corsHeaders });
            },

            "/o/authorize": async (req) => {
                const url = new URL(req.url);
                const clientId = url.searchParams.get("client_id");
                const redirectUri = url.searchParams.get("redirect_uri");
                const responseType = url.searchParams.get("response_type");
                const state = url.searchParams.get("state") ?? "";
                const scope = url.searchParams.get("scope") ?? "openid";

                if (!clientId || !redirectUri) {
                    return Response.json({ error: "client_id and redirect_uri are required." }, { status: 400, headers: corsHeaders });
                }
                if (responseType !== "code") {
                    return Response.json({ error: "Only response_type=code is supported." }, { status: 400, headers: corsHeaders });
                }

                const [client] = await pg`
                    SELECT id, redirect_uris, client_name FROM oidc_clients
                    WHERE client_id = ${clientId} AND is_active = true LIMIT 1
                `;
                if (!client) {
                    return Response.json({ error: "Invalid client_id." }, { status: 401, headers: corsHeaders });
                }
                if (!(client.redirect_uris as string[]).includes(redirectUri)) {
                    return Response.json({ error: "Invalid redirect_uri." }, { status: 401, headers: corsHeaders });
                }

                const loginUrl: URL = new URL("/o/authenticate", process.env.ISSUER_URL ?? server.url.origin);
                loginUrl.searchParams.set("client_id", clientId);
                loginUrl.searchParams.set("redirect_uri", redirectUri);
                loginUrl.searchParams.set("state", state);
                loginUrl.searchParams.set("scope", scope);
                if (client.client_name) {
                    loginUrl.searchParams.set("client_name", client.client_name);
                }
                return Response.redirect(loginUrl.toString(), 302);
            },

            "/o/authorize/callback": async (req) => {
                if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
                const { email, password, client_id, redirect_uri, state, scope } = await req.json() as any;
                if (!email || !password || !client_id || !redirect_uri) {
                    return Response.json({ error: "email, password, client_id, and redirect_uri are required." }, { status: 400, headers: corsHeaders });
                }

                const [client] = await pg`
                    SELECT id, redirect_uris FROM oidc_clients
                    WHERE client_id = ${client_id} AND is_active = true LIMIT 1
                `;
                if (!client || !(client.redirect_uris as string[]).includes(redirect_uri)) {
                    return Response.json({ error: "Invalid client or redirect_uri." }, { status: 401, headers: corsHeaders });
                }

                const [user] = await pg`SELECT * FROM users WHERE email = ${email} LIMIT 1`;
                if (!user?.password) {
                    return Response.json({ error: "Invalid credentials." }, { status: 401, headers: corsHeaders });
                }
                const isMatch = await Bun.password.verify(password, user.password);
                if (!isMatch) {
                    return Response.json({ error: "Invalid credentials." }, { status: 401, headers: corsHeaders });
                }

                const code = generateSecret(24); // shorter, URL-safe
                const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min

                await pg`
                    INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes, expires_at)
                    VALUES (${code}, ${client.id}, ${user.id}, ${redirect_uri}, ${scope ?? "openid"}, ${expiresAt})
                `;

                const callbackUrl = new URL(redirect_uri);
                callbackUrl.searchParams.set("code", code);
                if (state) callbackUrl.searchParams.set("state", state);

                // Return JSON instead of a 302 — the browser fetch in auth.html
                // cannot follow a cross-origin redirect (localhost:9000 → localhost:3001).
                // auth.html reads redirect_to and does window.location.href itself.
                return Response.json({ redirect_to: callbackUrl.toString() }, { headers: corsHeaders });
            },

            "/o/token": async (req) => {
                if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
                const body = await req.json() as any;
                const { grant_type, client_id, client_secret } = body;

                if (!client_id || !client_secret) {
                    return Response.json({ error: "client_id and client_secret are required." }, { status: 400, headers: corsHeaders });
                }

                const [client] = await pg`
                    SELECT id, client_secret_hash FROM oidc_clients
                    WHERE client_id = ${client_id} AND is_active = true LIMIT 1
                `;

                if (!client?.client_secret_hash) {
                    return Response.json({ error: "Invalid client." }, { status: 401, headers: corsHeaders });
                }
                const isClientValid = (await hashSecret(client_secret)) === client.client_secret_hash;
                if (!isClientValid) {
                    return Response.json({ error: "Invalid client secret." }, { status: 401, headers: corsHeaders });
                }

                const issueRefreshToken = async (userId: string) => {
                    const raw = generateSecret();
                    const hash = await hashSecret(raw);
                    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
                    await pg`
                        INSERT INTO refresh_tokens (token_hash, client_id, user_id, expires_at)
                        VALUES (${hash}, ${client.id}, ${userId}, ${expiresAt})
                    `;
                    return raw;
                };

                if (grant_type === "authorization_code") {
                    const { code, redirect_uri } = body;
                    if (!code || !redirect_uri) {
                        return Response.json({ error: "code and redirect_uri are required." }, { status: 400, headers: corsHeaders });
                    }

                    const [authCode] = await pg`
                        SELECT * FROM authorization_codes
                        WHERE code = ${code} AND client_id = ${client.id}
                          AND used = false AND expires_at > now()
                        LIMIT 1
                    `;

                    if (!authCode) {
                        return Response.json({ error: "Invalid or expired code." }, { status: 401, headers: corsHeaders });
                    }
                    if (authCode.redirectUri !== redirect_uri) {
                        return Response.json({ error: "redirect_uri mismatch." }, { status: 401, headers: corsHeaders });
                    }

                    await pg`UPDATE authorization_codes SET used = true WHERE id = ${authCode.id}`;

                    const [user] = await pg`SELECT * FROM users WHERE id = ${authCode.userId} LIMIT 1`;
                    if (!user) {
                        return Response.json({ error: "User not found." }, { status: 404, headers: corsHeaders });
                    }

                    const [id_token, refresh_token] = await Promise.all([
                        signUserToken(user, process.env.ISSUER_URL ?? server.url.origin),
                        issueRefreshToken(user.id),
                    ]) as any;

                    return Response.json({ id_token, refresh_token, token_type: "Bearer", expires_in: 3600 }, { headers: corsHeaders });

                } else if (grant_type === "refresh_token") {
                    const { refresh_token } = body;
                    if (!refresh_token) {
                        return Response.json({ error: "refresh_token is required." }, { status: 400, headers: corsHeaders });
                    }

                    const tokenHash = await hashSecret(refresh_token);
                    const [stored] = await pg`
                        SELECT * FROM refresh_tokens
                        WHERE token_hash = ${tokenHash} AND client_id = ${client.id}
                          AND revoked = false AND expires_at > now()
                        LIMIT 1
                    `;
                    if (!stored) {
                        return Response.json({ error: "Invalid or expired refresh token." }, { status: 401, headers: corsHeaders });
                    }

                    // Rotate: revoke old, issue new
                    await pg`UPDATE refresh_tokens SET revoked = true WHERE id = ${stored.id}`;

                    const [user] = await pg`SELECT * FROM users WHERE id = ${stored.userId} LIMIT 1`;
                    if (!user) {
                        return Response.json({ error: "User not found." }, { status: 404, headers: corsHeaders });
                    }

                    const [id_token, new_refresh_token] = await Promise.all([
                        signUserToken(user, process.env.ISSUER_URL ?? server.url.origin),
                        issueRefreshToken(user.id),
                    ]) as any;

                    return Response.json({ id_token, refresh_token: new_refresh_token, token_type: "Bearer", expires_in: 3600 }, { headers: corsHeaders });

                } else {
                    return Response.json({ error: "Unsupported grant_type." }, { status: 400, headers: corsHeaders });
                }
            },

            "/org/me": async (req) => {
                if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
                const claims = await verifyBearerToken(req, process.env.ISSUER_URL ?? server.url.origin);
                if (claims instanceof Response) return claims;

                const [org] = await pg`
                    SELECT id, name, slug FROM organizations
                    WHERE owner_user_id = ${claims.sub} LIMIT 1
                `;
                if (!org) {
                    return Response.json({ org: null, clients: [] }, { headers: corsHeaders });
                }

                const clients = await pg`
                    SELECT
                        id,
                        client_id        AS "clientId",
                        client_name      AS "clientName",
                        redirect_uris    AS "redirectUris",
                        is_active        AS "isActive",
                        created_at       AS "createdAt"
                    FROM oidc_clients WHERE organization_id = ${org.id}
                    ORDER BY created_at DESC
                `;

                return Response.json({ org, clients }, { headers: corsHeaders });
            },

            "/org/register": async (req) => {
                if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
                const claims = await verifyBearerToken(req, process.env.ISSUER_URL ?? server.url.origin);
                if (claims instanceof Response) return claims;

                const { name } = await req.json() as { name?: string };
                if (!name) {
                    return Response.json({ error: "Organization name is required." }, { status: 400, headers: corsHeaders });
                }

                const [user] = await pg`SELECT id FROM users WHERE id = ${claims.sub} LIMIT 1`;
                if (!user) {
                    return Response.json({ error: "User not found." }, { status: 404, headers: corsHeaders });
                }

                const [existingOrg] = await pg`SELECT id FROM organizations WHERE owner_user_id = ${claims.sub} LIMIT 1`;
                if (existingOrg) {
                    return Response.json({ error: "You already own an organization." }, { status: 409, headers: corsHeaders });
                }

                const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
                const [slugTaken] = await pg`SELECT id FROM organizations WHERE slug = ${slug} LIMIT 1`;
                if (slugTaken) {
                    return Response.json({ error: "Organization name is already taken." }, { status: 409, headers: corsHeaders });
                }

                const [org] = await pg`
                    INSERT INTO organizations (name, slug, owner_user_id)
                    VALUES (${name}, ${slug}, ${claims.sub})
                    RETURNING id, name, slug
                `;

                return Response.json({ message: "Organization created successfully.", org }, { status: 201, headers: corsHeaders });
            },


            "/org/clients/register": async (req) => {
                if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
                const claims = await verifyBearerToken(req, process.env.ISSUER_URL ?? server.url.origin);
                if (claims instanceof Response) return claims;

                const [org] = await pg`SELECT id FROM organizations WHERE owner_user_id = ${claims.sub} LIMIT 1`;
                if (!org) {
                    return Response.json({ error: "You don't own an organization." }, { status: 403, headers: corsHeaders });
                }

                const { client_name, redirect_uris } = await req.json() as any;
                if (!client_name || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
                    return Response.json({ error: "client_name and redirect_uris[] are required." }, { status: 400, headers: corsHeaders });
                }

                const clientSecret = generateSecret();
                const clientSecretHash = await hashSecret(clientSecret);

                // Bun's SQL client serialises JS arrays as plain strings, not PG array literals.
                // Build {"url1","url2"} format explicitly and cast with ::text[].
                const redirectUrisLiteral = toPostgresArray(redirect_uris as string[]);

                const [client] = await pg`
                    INSERT INTO oidc_clients (organization_id, client_name, client_secret_hash, redirect_uris)
                    VALUES (${org.id}, ${client_name}, ${clientSecretHash}, ${redirectUrisLiteral}::text[])
                    RETURNING id, client_id AS "clientId", client_name AS "clientName"
                `;

                return Response.json({
                    message: "Client registered. Save the client_secret — it won't be shown again.",
                    client_id: client.clientId,
                    client_secret: clientSecret,
                    client_name: client.clientName,
                }, { status: 201, headers: corsHeaders });

            },

        },

        error(error: any) {
            console.error("[server error]", error);

            if (error.name === "PostgresError") {
                return Response.json({ error: "Database error occurred." }, { status: 500, headers: corsHeaders });
            }

            return Response.json({ error: "Internal server error." }, { status: 500, headers: corsHeaders });
        },
    });

    console.log("Server is running on", process.env.ISSUER_URL ?? server.url.origin);
    return server;
};