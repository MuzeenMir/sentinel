import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export interface PlatformSettings {
  organizationName: string
  timezone: string
  autoBlockHighThreats: boolean
  drlAutoDecisions: boolean
  confidenceThreshold: number
  emailAlerts: boolean
  slackIntegration: boolean
}

const defaultSettings: PlatformSettings = {
  organizationName: 'SENTINEL Security',
  timezone: 'UTC',
  autoBlockHighThreats: true,
  drlAutoDecisions: true,
  confidenceThreshold: 85,
  emailAlerts: true,
  slackIntegration: false,
}

interface SettingsState extends PlatformSettings {
  setOrganizationName: (v: string) => void
  setTimezone: (v: string) => void
  setAutoBlockHighThreats: (v: boolean) => void
  setDrlAutoDecisions: (v: boolean) => void
  setConfidenceThreshold: (v: number) => void
  setEmailAlerts: (v: boolean) => void
  setSlackIntegration: (v: boolean) => void
  setAll: (s: Partial<PlatformSettings>) => void
  reset: () => void
}

export const useSettingsStore = create<SettingsState>()(
  persist(
    (set) => ({
      ...defaultSettings,
      setOrganizationName: (organizationName) => set({ organizationName }),
      setTimezone: (timezone) => set({ timezone }),
      setAutoBlockHighThreats: (autoBlockHighThreats) => set({ autoBlockHighThreats }),
      setDrlAutoDecisions: (drlAutoDecisions) => set({ drlAutoDecisions }),
      setConfidenceThreshold: (confidenceThreshold) => set({ confidenceThreshold }),
      setEmailAlerts: (emailAlerts) => set({ emailAlerts }),
      setSlackIntegration: (slackIntegration) => set({ slackIntegration }),
      setAll: (s) => set((state) => ({ ...state, ...s })),
      reset: () => set(defaultSettings),
    }),
    { name: 'sentinel-settings' }
  )
)
