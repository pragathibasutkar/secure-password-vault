import { api } from "./api.js";

async function getMasterKeyStatus() {
    if (typeof api.getMasterKey === "function") {
        return api.getMasterKey();
    }

    const response = await fetch("/master-key", { credentials: "include" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(data.detail || data.message || "Unable to load master key status.");
    }
    return data;
}

function clearSessionState() {
    localStorage.removeItem("spv_user");
    sessionStorage.removeItem("spv_master_password");
    sessionStorage.removeItem("spv_team_passphrase");
    sessionStorage.removeItem("spv_team_id");
}

export function setSession(user) {
    localStorage.setItem("spv_user", JSON.stringify(user));
}

export function getUser() {
    const raw = localStorage.getItem("spv_user");
    return raw ? JSON.parse(raw) : null;
}

export function clearSession() {
    clearSessionState();
}

export async function logout() {
    try {
        await api.logout();
    } catch {
        // Clear local state even if the cookie is already invalid.
    }
    clearSessionState();
    window.location.href = "./login.html";
}

export async function requireAuth() {
    try {
        const result = await api.getCurrentUser();
        setSession(result.user);
        return result.user;
    } catch {
        clearSessionState();
        window.location.href = "./login.html";
        return null;
    }
}

export async function requireUnlockedVault() {
    const user = await requireAuth();
    if (!user) {
        return null;
    }

    if (sessionStorage.getItem("spv_master_password")) {
        return user;
    }

    try {
        const masterKey = await getMasterKeyStatus();
        window.location.href = masterKey.configured ? "./vault-unlock.html" : "./master-key-setup.html";
    } catch {
        window.location.href = "./dashboard.html";
    }
    return null;
}

export function bindLogout() {
    const button = document.querySelector("#logout-button");
    if (button) {
        button.addEventListener("click", () => {
            logout();
        });
    }
}
