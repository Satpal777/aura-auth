import { SQL } from "bun";

type Migration = {
    version: number;
    run: () => Promise<void>;
};

const MIGRATIONS: Migration[] = [
    { version: 1, run: () => import("./migrations/m1").then(m => m.runMigrations()) },
    { version: 2, run: () => import("./migrations/m2").then(m => m.runMigrations()) },
    { version: 3, run: () => import("./migrations/m3").then(m => m.runMigrations()) },
    { version: 4, run: () => import("./migrations/m4").then(m => m.runMigrations()) },
];


export class Database {
    private static instance: SQL;

    private constructor() { }

    public static async getInstance(): Promise<SQL> {
        if (!Database.instance) {
            Database.instance = new SQL(process.env.DATABASE_URL!);

            try {
                await Database.instance`SELECT 1 FROM migrations LIMIT 1`;
            } catch {
                console.log("Migrations table does not exist. Creating...");
                await Database.instance`
                    CREATE TABLE IF NOT EXISTS migrations (
                        id      SERIAL    PRIMARY KEY,
                        run_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                `;
            } finally {
                const result = await Database.instance`
                    SELECT id FROM migrations ORDER BY id DESC LIMIT 1
                `;
                const version: number = result[0]?.id ?? 0;

                for (const migration of MIGRATIONS) {
                    if (version < migration.version) {
                        console.log(`Running migration m${migration.version}...`);
                        await migration.run();
                        await Database.instance`
                            INSERT INTO migrations (id) VALUES (${migration.version})
                        `;
                    }
                }

                console.log("DB connected & migrations ready!");
            }
        }

        return Database.instance;
    }
}