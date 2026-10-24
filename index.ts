import { createServer } from "./src/app";
import { logger } from "./src/utils/logger";

let server: Awaited<ReturnType<typeof createServer>> | null = null;

async function main() {
    server = await createServer();
}

function shutdown(signal: string) {
    logger.info("Shutdown signal received", { signal });

    if (server) {
        server.stop(true); // graceful: finish in-flight requests
        logger.info("Server stopped");
    }

    process.exit(0);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

main().catch((error) => {
    logger.error("Fatal error during startup", { error: String(error) });
    process.exit(1);
});
