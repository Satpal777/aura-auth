import { Database } from "../db";

/**
 * User table
 */
export async function runMigrations() {
  const db = await Database.getInstance();

  await db`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      first_name varchar(25),
      last_name varchar(25),
      profile_image_url text,
      email varchar(322) NOT NULL UNIQUE,
      email_verified boolean DEFAULT false NOT NULL,
      password varchar(66),
      created_at timestamp DEFAULT now() NOT NULL,
      updated_at timestamp
    );
  `;

  console.log("Migration v1 done!");
}