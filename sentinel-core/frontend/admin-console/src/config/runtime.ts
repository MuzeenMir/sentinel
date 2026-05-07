type RuntimeConfig = {
  apiUrl?: string;
  env?: string;
  appName?: string;
  supportEmail?: string;
};

const readRuntimeConfig = (): RuntimeConfig => {
  if (typeof window === "undefined") {
    return {};
  }

  return window.__SENTINEL__ || {};
};

const normalizeUrl = (value?: string) => {
  if (!value) {
    return "";
  }
  const trimmed = value.replace(/\/+$/, "");
  if (trimmed.endsWith("/api")) {
    return trimmed.slice(0, -4);
  }
  return trimmed;
};

const runtime = readRuntimeConfig();

export const appConfig = {
  apiBaseUrl: normalizeUrl(
    import.meta.env.VITE_API_URL || runtime.apiUrl || "",
  ),
  appEnv:
    import.meta.env.VITE_APP_ENV ||
    runtime.env ||
    import.meta.env.MODE ||
    "production",
  appName: import.meta.env.VITE_APP_NAME || runtime.appName || "SENTINEL",
  supportEmail:
    import.meta.env.VITE_SUPPORT_EMAIL ||
    runtime.supportEmail ||
    "security@sentinel.local",
};
