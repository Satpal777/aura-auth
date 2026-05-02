import { Database } from "../db";

/**
 * Organization & OIDC Client Tables
 */
export async function runMigrations() {
    const db = await Database.getInstance();

    await db`
        CREATE TABLE IF NOT EXISTS organizations (
            id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
            name          varchar(100) NOT NULL,
            slug          varchar(63)  NOT NULL UNIQUE,
            owner_user_id uuid        NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            is_active     boolean     NOT NULL DEFAULT true,
            created_at    timestamp   NOT NULL DEFAULT now()
        );
    `;

    await db`
        CREATE TABLE IF NOT EXISTS oidc_clients (
            id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id    uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            client_id          varchar(64) NOT NULL UNIQUE DEFAULT gen_random_uuid()::text,
            client_secret_hash varchar(128),
            client_name        varchar(100) NOT NULL,
            redirect_uris      text[]      NOT NULL DEFAULT '{}',
            is_active          boolean     NOT NULL DEFAULT true,
            created_at         timestamp   NOT NULL DEFAULT now()
        );
    `;

    await db`
        CREATE TABLE IF NOT EXISTS authorization_codes (
            id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
            code         varchar(128) NOT NULL UNIQUE,
            client_id    uuid        NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
            user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            redirect_uri text        NOT NULL,
            scopes       text        NOT NULL,
            used         boolean     NOT NULL DEFAULT false,
            expires_at   timestamp   NOT NULL,
            created_at   timestamp   NOT NULL DEFAULT now()
        );
    `;

    await db`
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
            token_hash   varchar(128) NOT NULL UNIQUE,
            client_id    uuid        NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
            user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            revoked      boolean     NOT NULL DEFAULT false,
            expires_at   timestamp   NOT NULL,
            created_at   timestamp   NOT NULL DEFAULT now()
        );
    `;

    console.log("Migration v2 done!");
}
