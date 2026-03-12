import { api } from "./api.js";
import { decryptVault, encryptVault } from "./crypto.js";
import { bindLogout, requireAuth } from "./session.js";
import { copyWithAutoClear, setMessage } from "./utils.js";

const state = {
    teamId: sessionStorage.getItem("spv_team_id") || "",
    teamPassphrase: sessionStorage.getItem("spv_team_passphrase") || "",
    role: "",
    items: [],
};

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function getMessageElement() {
    return document.querySelector("#team-message");
}

function canManage() {
    return state.role === "admin";
}

function resetForm() {
    document.querySelector("#team-form-title").textContent = "Add team entry";
    document.querySelector("#team-entry-id").value = "";
    document.querySelector("#team-vault-form").reset();
}

function setEmptyState(message) {
    const emptyState = document.querySelector("#team-empty-state");
    if (emptyState) {
        emptyState.textContent = message;
    }
}

function renderTable(rows) {
    const tbody = document.querySelector("#team-table-body");
    tbody.innerHTML = "";

    if (!rows.length) {
        setEmptyState("No team entries are visible yet.");
        return;
    }

    setEmptyState("");

    rows.forEach((item) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${escapeHtml(item.website)}</td>
            <td>${escapeHtml(item.username)}</td>
            <td><span class="pill">********</span></td>
            <td class="table-actions"></td>
        `;

        const pill = row.querySelector(".pill");
        const actions = row.querySelector(".table-actions");

        const showButton = document.createElement("button");
        showButton.type = "button";
        showButton.textContent = "Show";
        showButton.addEventListener("click", () => {
            pill.textContent = pill.textContent.includes("*") ? item.password : "********";
        });

        const copyButton = document.createElement("button");
        copyButton.type = "button";
        copyButton.className = "button-secondary";
        copyButton.textContent = "Copy";
        copyButton.addEventListener("click", () => copyWithAutoClear(item.password, getMessageElement()));

        actions.append(showButton, copyButton);

        if (canManage()) {
            const editButton = document.createElement("button");
            editButton.type = "button";
            editButton.className = "button-secondary";
            editButton.textContent = "Edit";
            editButton.addEventListener("click", () => {
                document.querySelector("#team-form-title").textContent = "Edit team entry";
                document.querySelector("#team-entry-id").value = item.id;
                document.querySelector("#team-website").value = item.website;
                document.querySelector("#team-username").value = item.username;
                document.querySelector("#team-password").value = item.password;
            });

            const deleteButton = document.createElement("button");
            deleteButton.type = "button";
            deleteButton.textContent = "Delete";
            deleteButton.addEventListener("click", async () => {
                try {
                    await api.deleteTeamVault(state.teamId, item.id);
                    setMessage(getMessageElement(), "Team vault entry deleted.");
                    await loadTeamVault();
                } catch (error) {
                    setMessage(getMessageElement(), error.message, true);
                }
            });
            actions.append(editButton, deleteButton);
        }

        tbody.appendChild(row);
    });
}

async function loadTeamVault() {
    if (!state.teamId) {
        renderTable([]);
        setEmptyState("Create or load a team to see shared vault entries.");
        return;
    }

    const result = await api.getTeamVault(state.teamId);
    state.role = result.role;
    state.items = result.items || [];

    if (!state.teamPassphrase) {
        renderTable([]);
        setMessage(getMessageElement(), `Team vault loaded with role ${state.role}. Enter passphrase to decrypt.`);
        setEmptyState("Team entries exist, but they are locked until you enter the shared passphrase.");
        return;
    }

    try {
        const decrypted = [];
        for (const item of state.items) {
            try {
                decrypted.push({
                    id: item.id,
                    ...(await decryptVault(item.encrypted_data, state.teamPassphrase)),
                });
            } catch {
                // Keep rendering decryptable rows even if one legacy row uses a different passphrase.
            }
        }
        renderTable(decrypted);
        if (state.items.length && !decrypted.length) {
            setMessage(getMessageElement(), "Team entries exist, but this passphrase could not decrypt them.", true);
            setEmptyState("Shared entries exist, but the current passphrase does not unlock them.");
        } else {
            setMessage(getMessageElement(), `Team vault ready. Role: ${state.role}.`);
        }
    } catch {
        renderTable([]);
        setMessage(getMessageElement(), "Unable to decrypt team entries with this passphrase.", true);
    }
}

async function init() {
    const authenticatedUser = await requireAuth();
    if (!authenticatedUser) {
        return;
    }
    bindLogout();

    if (state.teamId) {
        document.querySelector("#team-id").value = state.teamId;
    }
    if (state.teamPassphrase) {
        document.querySelector("#team-passphrase").value = state.teamPassphrase;
    }

    document.querySelector("#create-team-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const name = event.currentTarget.elements.name.value;
            const result = await api.createTeam({ name });
            state.teamId = result.team.id;
            sessionStorage.setItem("spv_team_id", state.teamId);
            document.querySelector("#team-id").value = state.teamId;
            setMessage(getMessageElement(), `Team created. Team ID: ${state.teamId}`);
            await loadTeamVault();
        } catch (error) {
            setMessage(getMessageElement(), error.message, true);
        }
    });

    document.querySelector("#add-member-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const form = event.currentTarget;
            await api.addMember({
                team_id: form.elements.team_id.value,
                email: form.elements.email.value,
                role: form.elements.role.value,
            });
            setMessage(getMessageElement(), "Member added to team.");
            form.reset();
        } catch (error) {
            setMessage(getMessageElement(), error.message, true);
        }
    });

    document.querySelector("#load-team-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            state.teamId = document.querySelector("#team-id").value;
            state.teamPassphrase = document.querySelector("#team-passphrase").value;
            sessionStorage.setItem("spv_team_id", state.teamId);
            sessionStorage.setItem("spv_team_passphrase", state.teamPassphrase);
            await loadTeamVault();
        } catch (error) {
            setMessage(getMessageElement(), error.message, true);
        }
    });

    document.querySelector("#team-vault-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            if (!state.teamId || !state.teamPassphrase) {
                setMessage(getMessageElement(), "Load a team and passphrase first.", true);
                return;
            }
            const encrypted_data = await encryptVault(
                {
                    website: document.querySelector("#team-website").value,
                    username: document.querySelector("#team-username").value,
                    password: document.querySelector("#team-password").value,
                },
                state.teamPassphrase,
            );
            const entryId = document.querySelector("#team-entry-id").value;
            if (entryId) {
                await api.updateTeamVault({ team_id: state.teamId, entry_id: entryId, encrypted_data });
                setMessage(getMessageElement(), "Encrypted team entry updated.");
            } else {
                await api.addTeamVault({ team_id: state.teamId, encrypted_data });
                setMessage(getMessageElement(), "Encrypted team entry added.");
            }
            resetForm();
            await loadTeamVault();
        } catch (error) {
            setMessage(getMessageElement(), error.message, true);
        }
    });

    try {
        await loadTeamVault();
    } catch (error) {
        setMessage(getMessageElement(), error.message, true);
    }
}

init().catch((error) => setMessage(getMessageElement(), error.message, true));
