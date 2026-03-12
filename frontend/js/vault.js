import { api } from "./api.js";
import { decryptVault, encryptVault } from "./crypto.js";
import { bindLogout, requireUnlockedVault } from "./session.js";
import { copyWithAutoClear, downloadJsonFile, readJsonFile, setMessage } from "./utils.js";

const state = {
    masterPassword: sessionStorage.getItem("spv_master_password") || "",
    encryptedItems: [],
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
    return document.querySelector("#vault-message");
}

function setEmptyState(message) {
    const element = document.querySelector("#vault-empty-state");
    if (element) {
        element.textContent = message;
    }
}

function setUnlockState(isUnlocked) {
    const status = document.querySelector("#unlock-status");
    const formFields = document.querySelectorAll("#vault-form input, #vault-form button");
    if (!status) {
        return;
    }

    status.textContent = isUnlocked ? "Unlocked" : "Locked";
    formFields.forEach((field) => {
        if (field.id !== "vault-id") {
            field.disabled = !isUnlocked;
        }
    });
}

function renderTable(items, lockedItems = []) {
    const tbody = document.querySelector("#vault-table-body");
    if (!tbody) {
        return;
    }

    tbody.innerHTML = "";

    if (!items.length && !lockedItems.length) {
        setEmptyState("No decrypted passwords are visible yet.");
        return;
    }

    setEmptyState("");

    items.forEach((item) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${escapeHtml(item.website)}</td>
            <td>${escapeHtml(item.username)}</td>
            <td><span class="pill" data-password>********</span></td>
            <td class="table-actions"></td>
        `;

        const passwordCell = row.querySelector("[data-password]");
        const actions = row.querySelector(".table-actions");

        const showButton = document.createElement("button");
        showButton.type = "button";
        showButton.textContent = "Show";
        showButton.addEventListener("click", () => {
            passwordCell.textContent = passwordCell.textContent.includes("*") ? item.password : "********";
        });

        const copyButton = document.createElement("button");
        copyButton.type = "button";
        copyButton.className = "button-secondary";
        copyButton.textContent = "Copy";
        copyButton.addEventListener("click", () => copyWithAutoClear(item.password, getMessageElement()));

        const editButton = document.createElement("button");
        editButton.type = "button";
        editButton.textContent = "Edit";
        editButton.addEventListener("click", () => {
            document.querySelector("#vault-form-title").textContent = "Edit password";
            document.querySelector("#vault-id").value = item.id;
            document.querySelector("#website").value = item.website;
            document.querySelector("#username").value = item.username;
            document.querySelector("#password").value = item.password;
        });

        const deleteButton = document.createElement("button");
        deleteButton.type = "button";
        deleteButton.className = "button-secondary";
        deleteButton.textContent = "Delete";
        deleteButton.addEventListener("click", async () => {
            try {
                await api.deleteVault(item.id);
                setMessage(getMessageElement(), "Vault entry deleted.");
                await loadVault();
            } catch (error) {
                setMessage(getMessageElement(), error.message, true);
            }
        });

        actions.append(showButton, copyButton, editButton, deleteButton);
        tbody.appendChild(row);
    });

    lockedItems.forEach((item, index) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>Encrypted entry ${index + 1}</td>
            <td><span class="pill">Locked</span></td>
            <td><span class="pill">********</span></td>
            <td class="table-actions"></td>
        `;

        const actions = row.querySelector(".table-actions");
        const deleteButton = document.createElement("button");
        deleteButton.type = "button";
        deleteButton.className = "button-muted";
        deleteButton.textContent = "Delete";
        deleteButton.addEventListener("click", async () => {
            try {
                await api.deleteVault(item.id);
                setMessage(getMessageElement(), "Locked vault entry deleted.");
                await loadVault();
            } catch (error) {
                setMessage(getMessageElement(), error.message, true);
            }
        });
        actions.append(deleteButton);
        tbody.appendChild(row);
    });
}

async function decryptEntries() {
    if (!state.masterPassword) {
        setUnlockState(false);
        renderTable([]);
        setMessage(getMessageElement(), "Unlock the vault first.", true);
        return;
    }

    const decrypted = [];
    const locked = [];

    for (const item of state.encryptedItems) {
        try {
            decrypted.push({
                id: item.id,
                ...(await decryptVault(item.encrypted_data, state.masterPassword)),
            });
        } catch {
            locked.push(item);
        }
    }

    renderTable(decrypted, locked);
    setUnlockState(true);

    if (decrypted.length && !locked.length) {
        setMessage(getMessageElement(), "Vault unlocked.");
    } else if (decrypted.length && locked.length) {
        setMessage(
            getMessageElement(),
            `${decrypted.length} entries decrypted. ${locked.length} entries could not be decrypted with this master key.`,
            true,
        );
    } else if (!decrypted.length && locked.length) {
        setMessage(getMessageElement(), "Entries exist, but this master key could not decrypt them.", true);
        setEmptyState("Saved entries exist, but this master key does not unlock them.");
    } else {
        setMessage(getMessageElement(), "Vault unlocked. No entries yet, add your first password.");
        setEmptyState("No passwords saved yet. Use the form above to create your first entry.");
    }
}

async function loadVault() {
    const result = await api.getVault();
    state.encryptedItems = result.items || [];
    await decryptEntries();
}

function resetForm() {
    document.querySelector("#vault-form-title").textContent = "Add password";
    document.querySelector("#vault-form").reset();
    document.querySelector("#vault-id").value = "";
}

async function init() {
    const authenticatedUser = await requireUnlockedVault();
    if (!authenticatedUser) {
        return;
    }

    bindLogout();
    setUnlockState(Boolean(state.masterPassword));

    document.querySelector("#lock-vault-session").addEventListener("click", () => {
        sessionStorage.removeItem("spv_master_password");
        window.location.href = "./vault-unlock.html";
    });

    document.querySelector("#focus-add-password").addEventListener("click", () => {
        document.querySelector("#password-form-card").scrollIntoView({ behavior: "smooth", block: "start" });
        document.querySelector("#website").focus();
    });

    document.querySelector("#reset-vault-form")?.addEventListener("click", () => {
        resetForm();
        setMessage(getMessageElement(), "Form cleared.");
    });

    document.querySelector("#vault-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            if (!state.masterPassword) {
                throw new Error("Unlock the vault first.");
            }

            const record = {
                website: document.querySelector("#website").value.trim(),
                username: document.querySelector("#username").value.trim(),
                password: document.querySelector("#password").value,
            };
            if (!record.website || !record.username || !record.password) {
                throw new Error("Fill website, username, and password before saving.");
            }

            const encrypted_data = await encryptVault(record, state.masterPassword);
            const existingId = document.querySelector("#vault-id").value;

            if (existingId) {
                await api.updateVault({ id: existingId, encrypted_data });
                setMessage(getMessageElement(), "Vault entry updated.");
            } else {
                await api.addVault({ encrypted_data });
                setMessage(getMessageElement(), "Vault entry added.");
            }

            resetForm();
            await loadVault();
        } catch (error) {
            setMessage(getMessageElement(), error.message, true);
        }
    });

    document.querySelector("#export-backup").addEventListener("click", () => {
        downloadJsonFile("vault_backup.enc", {
            exported_at: new Date().toISOString(),
            items: state.encryptedItems,
        });
        setMessage(getMessageElement(), "Encrypted backup downloaded.");
    });

    document.querySelector("#import-backup").addEventListener("change", async (event) => {
        try {
            const file = event.target.files[0];
            if (!file) {
                return;
            }
            const payload = await readJsonFile(file);
            for (const item of payload.items || []) {
                await api.addVault({ encrypted_data: item.encrypted_data });
            }
            setMessage(getMessageElement(), "Encrypted backup imported.");
            await loadVault();
        } catch (error) {
            setMessage(getMessageElement(), error.message, true);
        }
    });

    try {
        await loadVault();
    } catch (error) {
        setMessage(getMessageElement(), error.message, true);
    }
}

init().catch((error) => setMessage(getMessageElement(), error.message, true));
