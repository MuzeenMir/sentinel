/// <reference types="vite/client" />

declare global {
  interface ImportMetaEnv {
    readonly VITE_API_URL?: string
    readonly VITE_APP_ENV?: string
    readonly VITE_DEMO_AUTH?: string
    readonly VITE_APP_NAME?: string
    readonly VITE_SUPPORT_EMAIL?: string
  }
  interface Window {
    __SENTINEL__?: {
      apiUrl?: string
      env?: string
      demoAuth?: boolean | string
      appName?: string
      supportEmail?: string
    }
  }
}

export {}
