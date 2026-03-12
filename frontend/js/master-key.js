import { api } from "./api.js";
import { createMasterKeyVerifier, verifyMasterKey } from "./crypto.js";
import { requireAuth } from "./session.js";
import { setMessage } from "./utils.js";

async function initSetupPage() {
    const user = await requireAuth();
    if (!user) {
        return;
    }

    const masterKey = await api.getMasterKey();
    if (masterKey.configured) {
        window.location.href = "./vault-unlock.html";
        return;
    }

    const form = document.querySelector("#master-key-setup-form");
    const message = document.querySelector("#master-key-message");

    form?.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const password = form.elements.master_key.value;
            const confirmPassword = form.elements.confirm_master_key.value;

            if (password.length < 8) {
                throw new Error("Master key must be at least 8 characters long.");
            }

            if (password !== confirmPassword) {
                throw new Error("Master key confirmation does not match.");
            }

            const verifier = await createMasterKeyVerifier(password);
            await api.createMasterKey({ verifier });
            sessionStorage.setItem("spv_master_password", password);
            setMessage(message, "Master key created. Redirecting to vault...");
            window.setTimeout(() => {
                window.location.href = "./vault.html";
            }, 700);
        } catch (error) {
            setMessage(message, error.message, true);
        }
    });
}

async function initUnlockPage() {
    const user = await requireAuth();
    if (!user) {
        return;
    }

    const masterKey = await api.getMasterKey();
    if (!masterKey.configured || !masterKey.verifier) {
        window.location.href = "./master-key-setup.html";
        return;
    }

    const form = document.querySelector("#vault-unlock-form");
    const message = document.querySelector("#vault-unlock-message");

    form?.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const password = form.elements.master_key.value;
            const isValid = await verifyMasterKey(password, masterKey.verifier);
            if (!isValid) {
                throw new Error("Incorrect master key.");
            }

            sessionStorage.setItem("spv_master_password", password);
            setMessage(message, "Vault unlocked. Redirecting...");
            window.setTimeout(() => {
                window.location.href = "./vault.html";
            }, 500);
        } catch (error) {
            setMessage(message, error.message, true);
        }
    });
}

async function init() {
    if (document.body.dataset.page === "master-key-setup") {
        await initSetupPage();
    }

    if (document.body.dataset.page === "vault-unlock") {
        await initUnlockPage();
    }
}

init().catch((error) => {
    const message = document.querySelector("#master-key-message") || document.querySelector("#vault-unlock-message");
    if (message) {
        setMessage(message, error.message || "Unable to load page.", true);
    }
});
