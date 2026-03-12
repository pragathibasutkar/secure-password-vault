const page = document.body.dataset.page;

const pageModules = {
    login: "./auth.js",
    signup: "./auth.js",
    "forgot-password": "./auth.js",
    "master-key-setup": "./master-key.js",
    "vault-unlock": "./master-key.js",
    dashboard: "./dashboard.js",
    vault: "./vault.js",
    "team-vault": "./team-vault.js",
};

function initSidebar() {
    const sidebar = document.querySelector("[data-sidebar]");
    const overlay = document.querySelector("[data-sidebar-overlay]");
    const openButton = document.querySelector("[data-sidebar-open]");
    const closeButton = document.querySelector("[data-sidebar-close]");

    if (!sidebar || !overlay || !openButton || !closeButton) {
        return;
    }

    const closeSidebar = () => {
        sidebar.classList.remove("open");
        overlay.classList.remove("open");
    };

    const openSidebar = () => {
        sidebar.classList.add("open");
        overlay.classList.add("open");
    };

    openButton.addEventListener("click", openSidebar);
    closeButton.addEventListener("click", closeSidebar);
    overlay.addEventListener("click", closeSidebar);
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            closeSidebar();
        }
    });
}

function initVaultSettingsPanels() {
    const triggers = document.querySelectorAll("[data-panel-target]");
    const panels = document.querySelectorAll("[data-panel]");

    if (!triggers.length || !panels.length) {
        return;
    }

    triggers.forEach((trigger) => {
        trigger.addEventListener("click", () => {
            const target = trigger.dataset.panelTarget;
            panels.forEach((panel) => {
                panel.classList.toggle("active", panel.dataset.panel === target);
            });
            triggers.forEach((item) => item.classList.remove("active"));
            trigger.classList.add("active");
            if (trigger.id) {
                window.location.hash = trigger.id;
            }
        });
    });

    const hash = window.location.hash.replace("#", "");
    if (!hash) {
        return;
    }

    const matchingTrigger = document.getElementById(hash);
    if (matchingTrigger?.dataset.panelTarget) {
        matchingTrigger.click();
    }
}

function mirrorLogoutButton() {
    const sidebarLogout = document.querySelector("#sidebar-logout-button");
    const topLogout = document.querySelector("#logout-button");
    if (!sidebarLogout || !topLogout) {
        return;
    }

    sidebarLogout.addEventListener("click", () => {
        topLogout.click();
    });
}

if (pageModules[page]) {
    import(pageModules[page]);
}

initSidebar();
initVaultSettingsPanels();
mirrorLogoutButton();
