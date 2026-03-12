function toBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    bytes.forEach((byte) => {
        binary += String.fromCharCode(byte);
    });
    return btoa(binary);
}

function fromBase64(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
}

function getRandomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
}

const PBKDF2_ITERATIONS = 250000;

async function getKeyMaterial(password) {
    const encoder = new TextEncoder();
    return crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"],
    );
}

async function derivePasswordBits(password, saltBase64) {
    const keyMaterial = await getKeyMaterial(password);
    const salt = saltBase64 ? fromBase64(saltBase64) : getRandomBytes(16);
    const bits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256",
        },
        keyMaterial,
        256,
    );
    return { bits, salt: toBase64(salt.buffer) };
}

export async function generateKey(masterPassword, saltBase64) {
    const keyMaterial = await getKeyMaterial(masterPassword);
    const salt = saltBase64 ? fromBase64(saltBase64) : getRandomBytes(16);
    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
    );

    return { key, salt: toBase64(salt.buffer) };
}

export async function encryptVault(data, masterPassword) {
    const { key, salt } = await generateKey(masterPassword);
    const iv = getRandomBytes(12);
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);

    return {
        version: 1,
        algorithm: "AES-GCM",
        salt,
        iv: toBase64(iv.buffer),
        ciphertext: toBase64(encrypted),
    };
}

export async function decryptVault(payload, masterPassword) {
    const { key } = await generateKey(masterPassword, payload.salt);
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromBase64(payload.iv) },
        key,
        fromBase64(payload.ciphertext),
    );

    return JSON.parse(new TextDecoder().decode(decrypted));
}

export async function createMasterKeyVerifier(masterPassword) {
    const { bits, salt } = await derivePasswordBits(masterPassword);
    return {
        version: 1,
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: toBase64(bits),
    };
}

export async function verifyMasterKey(masterPassword, verifier) {
    if (!verifier?.salt || !verifier?.hash) {
        return false;
    }
    const { bits } = await derivePasswordBits(masterPassword, verifier.salt);
    return toBase64(bits) === verifier.hash;
}
