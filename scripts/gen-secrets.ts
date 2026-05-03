import { generateKeyPair, exportSPKI, exportPKCS8 } from "jose";
import { mkdirSync, readdirSync, writeFileSync } from "fs";
import { join } from "path";

const CERT_DIR = "./certs";

function getKid() {
    return `key-${Date.now()}`;
}

async function rotateKeys() {
    mkdirSync(CERT_DIR, { recursive: true });

    const kid = getKid();

    const { publicKey, privateKey } = await generateKeyPair("RS256", {
        extractable: true,
    });

    const publicPem = await exportSPKI(publicKey);
    const privatePem = await exportPKCS8(privateKey);

    const pubPath = join(CERT_DIR, `${kid}.public.pem`);
    const privPath = join(CERT_DIR, `${kid}.private.pem`);

    writeFileSync(pubPath, publicPem);
    writeFileSync(privPath, privatePem);

    const files = readdirSync(CERT_DIR)
        .filter(f => f.endsWith(".pem"))
        .sort();

    const groups: Record<string, string[]> = {};

    for (const file of files) {
        const [kid] = file.split(".");

        if (!kid) continue;

        if (!groups[kid]) groups[kid] = [];
        groups[kid].push(file);
    }
}

rotateKeys();