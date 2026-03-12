export function formToObject(form) {
    return Object.fromEntries(new FormData(form).entries());
}

export function setMessage(element, message, isError = false) {
    if (!element) {
        return;
    }
    element.textContent = message;
    element.classList.toggle("error", isError);
}

export async function copyWithAutoClear(value, messageElement) {
    try {
        await navigator.clipboard.writeText(value);
        setMessage(messageElement, "Copied to clipboard. It will be cleared in 10 seconds.");
        window.setTimeout(async () => {
            try {
                await navigator.clipboard.writeText("");
                setMessage(messageElement, "Clipboard cleared.");
            } catch {
                setMessage(messageElement, "Clipboard clear failed. Clear it manually if needed.", true);
            }
        }, 10000);
    } catch {
        setMessage(messageElement, "Clipboard access was blocked by the browser.", true);
    }
}

export function downloadJsonFile(fileName, payload) {
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    URL.revokeObjectURL(url);
}

export async function readJsonFile(file) {
    return JSON.parse(await file.text());
}
