import { createServer } from "./src/app";

try {
    createServer();
} catch (error) {
    console.error("Error starting the server:", error);
    process.exit(1);
}

