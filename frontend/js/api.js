import { API_BASE_URL } from "./config.js";

function clearCachedSession() {
    localStorage.removeItem("spv_user");
    sessionStorage.removeItem("spv_master_password");
    sessionStorage.removeItem("spv_team_passphrase");
    sessionStorage.removeItem("spv_team_id");
}

function handleUnauthorized() {
    clearCachedSession();
    if (!window.location.pathname.endsWith("/login.html")) {
        window.location.href = "./login.html";
    }
}

async function request(path, options = {}) {
    const headers = {
        "Content-Type": "application/json",
        ...(options.headers || {}),
    };

    let response;
    try {
        response = await fetch(`${API_BASE_URL}${path}`, {
            ...options,
            headers,
            credentials: "include",
        });
    } catch {
        throw new Error(`Unable to reach API at ${API_BASE_URL}`);
    }

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        if (response.status === 401) {
            handleUnauthorized();
        }
        throw new Error(data.detail || data.message || "Request failed");
    }
    return data;
}

export const api = {
    getPublicConfig() {
        return request("/public-config");
    },
    signup(payload) {
        return request("/signup", { method: "POST", body: JSON.stringify(payload) });
    },
    login(payload) {
        return request("/login", { method: "POST", body: JSON.stringify(payload) });
    },
    logout() {
        return request("/logout", { method: "POST" });
    },
    getCurrentUser() {
        return request("/me");
    },
    getMasterKey() {
        return request("/master-key");
    },
    createMasterKey(payload) {
        return request("/master-key", { method: "POST", body: JSON.stringify(payload) });
    },
    updateMasterKey(payload) {
        return request("/master-key", { method: "PUT", body: JSON.stringify(payload) });
    },
    forgotPassword(payload) {
        return request("/forgot-password", { method: "POST", body: JSON.stringify(payload) });
    },
    verifyOtp(payload) {
        return request("/verify-otp", { method: "POST", body: JSON.stringify(payload) });
    },
    resetPassword(payload) {
        return request("/reset-password", { method: "POST", body: JSON.stringify(payload) });
    },
    getVault() {
        return request("/vault");
    },
    addVault(payload) {
        return request("/vault/add", { method: "POST", body: JSON.stringify(payload) });
    },
    updateVault(payload) {
        return request("/vault/update", { method: "PUT", body: JSON.stringify(payload) });
    },
    deleteVault(id) {
        return request(`/vault/delete?id=${encodeURIComponent(id)}`, { method: "DELETE" });
    },
    createTeam(payload) {
        return request("/team/create", { method: "POST", body: JSON.stringify(payload) });
    },
    addMember(payload) {
        return request("/team/add-member", { method: "POST", body: JSON.stringify(payload) });
    },
    getTeamVault(teamId) {
        return request(`/team/vault?team_id=${encodeURIComponent(teamId)}`);
    },
    addTeamVault(payload) {
        return request("/team/vault/add", { method: "POST", body: JSON.stringify(payload) });
    },
    updateTeamVault(payload) {
        return request("/team/vault/update", { method: "PUT", body: JSON.stringify(payload) });
    },
    deleteTeamVault(teamId, entryId) {
        return request(
            `/team/vault/delete?team_id=${encodeURIComponent(teamId)}&entry_id=${encodeURIComponent(entryId)}`,
            { method: "DELETE" },
        );
    },
};
