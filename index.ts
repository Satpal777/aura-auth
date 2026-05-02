import { createServer } from "./src/app";
import { Database } from "./src/db/db";

console.log("Hello, Aura Auth!");

try {
    const server = createServer();
    console.log(`Server is running on ${server.url}`);
} catch (error) {
    console.error("Error starting the server:", error);
    process.exit(1);
}

