import { Database } from "../db";

/**
 * Widen oidc_clients.client_secret_hash from varchar(66) to text.
 * Bun.password.hash() uses argon2id by default (~97 chars), which exceeds the original limit.
 */
export async function runMigrations() {
    const db = await Database.getInstance();

    await db`ALTER TABLE oidc_clients ALTER COLUMN client_secret_hash TYPE text`;

    console.log("Migration v4 done!");
}
