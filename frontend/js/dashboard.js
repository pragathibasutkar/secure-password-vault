import { api } from "./api.js";
import { bindLogout, requireAuth } from "./session.js";

async function init() {
    const authenticatedUser = await requireAuth();
    if (!authenticatedUser) {
        return;
    }
    bindLogout();

    if (authenticatedUser) {
        document.querySelector("#session-email").textContent = `Signed in as ${authenticatedUser.email}`;
    }

    try {
        const vault = await api.getVault();
        document.querySelector("#vault-count").textContent = String(vault.items.length);
    } catch {
        document.querySelector("#vault-count").textContent = "!";
    }

    const teamId = sessionStorage.getItem("spv_team_id");
    if (!teamId) {
        document.querySelector("#team-count").textContent = "0";
        return;
    }

    try {
        const teamVault = await api.getTeamVault(teamId);
        document.querySelector("#team-count").textContent = String(teamVault.items.length);
    } catch {
        document.querySelector("#team-count").textContent = "!";
    }
}

init();
