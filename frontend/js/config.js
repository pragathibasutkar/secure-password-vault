function trimTrailingSlash(value) {
    return value.replace(/\/+$/, "");
}

function resolveApiBaseUrl() {
    const configured =
        window.localStorage.getItem("spv_api_base_url") ||
        document.querySelector('meta[name="api-base-url"]')?.content ||
        window.__SPV_API_BASE_URL__;

    if (configured) {
        return trimTrailingSlash(configured);
    }

    const { protocol, hostname, origin } = window.location;
    if (protocol === "http:" || protocol === "https:") {
        if (hostname === "127.0.0.1" || hostname === "localhost") {
            return "http://127.0.0.1:8000";
        }
        return trimTrailingSlash(origin);
    }

    return "http://127.0.0.1:8000";
}

export const API_BASE_URL = resolveApiBaseUrl();
