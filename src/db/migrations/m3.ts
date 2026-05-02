import { Database } from "../db";

/**
 * Widen users.password from varchar(66) to text.
 * Bun.password.hash() uses argon2id by default (~97 chars), which exceeds the original limit.
 */
export async function runMigrations() {
    const db = await Database.getInstance();

    await db`ALTER TABLE users ALTER COLUMN password TYPE text`;

    console.log("Migration v3 done!");
}
