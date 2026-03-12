import { api } from "./api.js";
import { setSession } from "./session.js";
import { formToObject, setMessage } from "./utils.js";

let publicConfigPromise;
let turnstileLoaderPromise;

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

function getPublicConfig() {
    if (!publicConfigPromise) {
        publicConfigPromise = api.getPublicConfig();
    }
    return publicConfigPromise;
}

function updateStrength(input, bar, label) {
    if (!input || !bar || !label || typeof window.zxcvbn !== "function") {
        return;
    }

    input.addEventListener("input", () => {
        const score = window.zxcvbn(input.value).score;
        const states = [
            { text: "Weak", width: "22%", className: "weak" },
            { text: "Weak", width: "36%", className: "weak" },
            { text: "Fair", width: "56%", className: "medium" },
            { text: "Strong", width: "78%", className: "strong" },
            { text: "Excellent", width: "100%", className: "strong" },
        ];
        const state = states[score];
        bar.className = `strength-fill ${state.className}`;
        bar.style.width = state.width;
        label.textContent = `Password strength: ${state.text}`;
    });
}

function setSubmitEnabled(form, enabled) {
    const submitButton = form?.querySelector('button[type="submit"]');
    if (submitButton) {
        submitButton.disabled = !enabled;
    }
}

function buildDemoCaptcha(container) {
    const question = container.querySelector("[data-captcha-question]");
    const answer = container.querySelector("[data-captcha-answer]");
    const verifyButton = container.querySelector("[data-captcha-verify]");
    const resetButton = container.querySelector("[data-captcha-reset]");
    const status = container.querySelector("[data-captcha-status]");
    const tokenField = container.querySelector('input[name="captcha_token"]');
    const demoSection = container.querySelector("[data-captcha-demo]");
    const turnstileSection = container.querySelector("[data-captcha-turnstile]");

    demoSection?.classList.remove("hidden");
    turnstileSection?.classList.add("hidden");
    verifyButton?.classList.remove("hidden");
    resetButton?.classList.remove("hidden");

    const state = { expected: 0, verified: false };

    function resetChallenge() {
        const left = Math.floor(Math.random() * 8) + 2;
        const right = Math.floor(Math.random() * 8) + 2;
        state.expected = left + right;
        state.verified = false;
        question.textContent = `${left} + ${right}`;
        answer.value = "";
        tokenField.value = "";
        status.textContent = "Development mode: solve the challenge and click Verify.";
        status.classList.remove("success", "error");
    }

    answer?.addEventListener("input", () => {
        state.verified = false;
        tokenField.value = "";
        status.textContent = "Development mode: solve the challenge and click Verify.";
        status.classList.remove("success", "error");
    });

    verifyButton?.addEventListener("click", () => {
        const submitted = Number(answer.value.trim());
        if (submitted === state.expected) {
            state.verified = true;
            tokenField.value = "demo-captcha-pass";
            status.textContent = "Verification complete.";
            status.classList.add("success");
            status.classList.remove("error");
            return;
        }

        state.verified = false;
        tokenField.value = "";
        status.textContent = "Incorrect answer. Try again.";
        status.classList.add("error");
        status.classList.remove("success");
    });

    resetButton?.addEventListener("click", resetChallenge);
    resetChallenge();

    return {
        ensureVerified() {
            if (!state.verified) {
                throw new Error("Please complete the CAPTCHA verification first.");
            }
        },
        reset() {
            resetChallenge();
        },
    };
}

function loadTurnstileScript() {
    if (window.turnstile) {
        return Promise.resolve(window.turnstile);
    }

    if (!turnstileLoaderPromise) {
        turnstileLoaderPromise = new Promise((resolve, reject) => {
            const existing = document.querySelector('script[data-turnstile-script="true"]');
            if (existing) {
                existing.addEventListener("load", () => resolve(window.turnstile), { once: true });
                existing.addEventListener("error", () => reject(new Error("Turnstile failed to load.")), { once: true });
                return;
            }

            const script = document.createElement("script");
            script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
            script.async = true;
            script.defer = true;
            script.dataset.turnstileScript = "true";
            script.onload = () => resolve(window.turnstile);
            script.onerror = () => reject(new Error("Turnstile failed to load."));
            document.head.append(script);
        });
    }

    return turnstileLoaderPromise;
}

async function buildTurnstileCaptcha(container, siteKey) {
    const tokenField = container.querySelector('input[name="captcha_token"]');
    const status = container.querySelector("[data-captcha-status]");
    const demoSection = container.querySelector("[data-captcha-demo]");
    const turnstileSection = container.querySelector("[data-captcha-turnstile]");
    const mountPoint = container.querySelector("[data-turnstile-mount]");
    const verifyButton = container.querySelector("[data-captcha-verify]");
    const resetButton = container.querySelector("[data-captcha-reset]");
    let token = "";
    let widgetId = null;

    demoSection?.classList.add("hidden");
    turnstileSection?.classList.remove("hidden");
    verifyButton?.classList.add("hidden");
    resetButton?.classList.remove("hidden");
    status.textContent = "Complete the security verification.";
    status.classList.remove("success", "error");
    tokenField.value = "";

    const turnstile = await loadTurnstileScript();
    widgetId = turnstile.render(mountPoint, {
        sitekey: siteKey,
        theme: "light",
        callback(value) {
            token = value;
            tokenField.value = value;
            status.textContent = "Verification complete.";
            status.classList.add("success");
            status.classList.remove("error");
        },
        "expired-callback"() {
            token = "";
            tokenField.value = "";
            status.textContent = "Verification expired. Please complete it again.";
            status.classList.add("error");
            status.classList.remove("success");
        },
        "error-callback"() {
            token = "";
            tokenField.value = "";
            status.textContent = "Captcha failed to load. Refresh and try again.";
            status.classList.add("error");
            status.classList.remove("success");
        },
    });

    resetButton?.addEventListener("click", () => {
        if (widgetId !== null && window.turnstile) {
            window.turnstile.reset(widgetId);
        }
        token = "";
        tokenField.value = "";
        status.textContent = "Complete the security verification.";
        status.classList.remove("success", "error");
    });

    return {
        ensureVerified() {
            if (!token) {
                throw new Error("Please complete the CAPTCHA verification first.");
            }
        },
        reset() {
            if (widgetId !== null && window.turnstile) {
                window.turnstile.reset(widgetId);
            }
            token = "";
            tokenField.value = "";
        },
    };
}

async function buildCaptcha(container) {
    if (!container) {
        return null;
    }

    const config = await getPublicConfig();
    if (config.captcha?.provider === "turnstile" && config.captcha.site_key) {
        return buildTurnstileCaptcha(container, config.captcha.site_key);
    }
    return buildDemoCaptcha(container);
}

async function handleLoginPage() {
    const form = document.querySelector("#login-form");
    const message = document.querySelector("#auth-message");
    setSubmitEnabled(form, false);
    const captcha = await buildCaptcha(document.querySelector("#login-captcha"));
    setSubmitEnabled(form, true);

    form?.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            captcha?.ensureVerified();
            const result = await api.login(formToObject(form));
            sessionStorage.removeItem("spv_master_password");
            sessionStorage.removeItem("spv_team_passphrase");
            sessionStorage.removeItem("spv_team_id");
            setSession(result.user);
            const masterKey = await getMasterKeyStatus();
            window.location.href = masterKey.configured ? "./vault-unlock.html" : "./master-key-setup.html";
        } catch (error) {
            captcha?.reset?.();
            setMessage(message, error.message, true);
        }
    });

    updateStrength(
        document.querySelector("#login-password"),
        document.querySelector("#login-strength-bar"),
        document.querySelector("#login-strength-text"),
    );
}

async function handleSignupPage() {
    const form = document.querySelector("#signup-form");
    const message = document.querySelector("#auth-message");
    setSubmitEnabled(form, false);
    const captcha = await buildCaptcha(document.querySelector("#signup-captcha"));
    setSubmitEnabled(form, true);

    form?.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            captcha?.ensureVerified();
            const result = await api.signup(formToObject(form));
            setMessage(message, `${result.message}. Redirecting to login...`);
            window.setTimeout(() => {
                window.location.href = "./login.html";
            }, 1200);
        } catch (error) {
            captcha?.reset?.();
            setMessage(message, error.message, true);
        }
    });

    updateStrength(
        document.querySelector("#signup-password"),
        document.querySelector("#signup-strength-bar"),
        document.querySelector("#signup-strength-text"),
    );
}

async function handleForgotPasswordPage() {
    const forgotForm = document.querySelector("#forgot-form");
    const verifyForm = document.querySelector("#verify-otp-form");
    const resetForm = document.querySelector("#reset-form");
    const message = document.querySelector("#forgot-message");
    const devPanel = document.querySelector("#recovery-dev-panel");
    const devOtp = document.querySelector("#development-otp");
    const tokenField = document.querySelector('textarea[name="reset_token"]');
    const verifyEmailField = document.querySelector('#verify-otp-form input[name="email"]');

    setSubmitEnabled(forgotForm, false);
    const forgotCaptcha = await buildCaptcha(document.querySelector("#forgot-captcha"));
    setSubmitEnabled(forgotForm, true);

    forgotForm?.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            forgotCaptcha?.ensureVerified();
            const payload = formToObject(forgotForm);
            const result = await api.forgotPassword(payload);
            if (verifyEmailField) {
                verifyEmailField.value = payload.email;
            }
            if (result.development_otp && devPanel && devOtp) {
                devPanel.hidden = false;
                devPanel.classList.remove("hidden");
                devOtp.value = result.development_otp;
                verifyForm.elements.otp.value = result.development_otp;
            } else if (devPanel) {
                devPanel.hidden = true;
                devPanel.classList.add("hidden");
            }
            setMessage(message, result.development_otp ? "OTP generated for development mode." : result.message);
        } catch (error) {
            forgotCaptcha?.reset?.();
            setMessage(message, error.message, true);
        }
    });

    verifyForm?.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const result = await api.verifyOtp(formToObject(verifyForm));
            tokenField.value = result.reset_token;
            setMessage(message, "OTP verified. Set your new password below.");
            resetForm.elements.new_password.focus();
        } catch (error) {
            setMessage(message, error.message, true);
        }
    });

    resetForm?.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const payload = formToObject(resetForm);
            if (!payload.reset_token.trim()) {
                throw new Error("Verify your OTP first so the reset token can be generated.");
            }
            const result = await api.resetPassword(payload);
            resetForm.reset();
            setMessage(message, `${result.message}. Redirecting to login...`);
            window.setTimeout(() => {
                window.location.href = "./login.html";
            }, 1400);
        } catch (error) {
            setMessage(message, error.message, true);
        }
    });

    updateStrength(
        document.querySelector("#reset-password"),
        document.querySelector("#reset-strength-bar"),
        document.querySelector("#reset-strength-text"),
    );
}

async function boot() {
    if (document.body.dataset.page === "login") {
        await handleLoginPage();
    }

    if (document.body.dataset.page === "signup") {
        await handleSignupPage();
    }

    if (document.body.dataset.page === "forgot-password") {
        await handleForgotPasswordPage();
    }
}

boot().catch((error) => {
    const authMessage = document.querySelector("#auth-message") || document.querySelector("#forgot-message");
    if (authMessage) {
        setMessage(authMessage, error.message || "Unable to load authentication page.", true);
    }
});
