import { describe, it, expect, beforeEach } from 'vitest'
import { useSettingsStore } from './settingsStore'
import type { PlatformSettings } from './settingsStore'

const defaults: PlatformSettings = {
  organizationName: 'SENTINEL Security',
  timezone: 'UTC',
  autoBlockHighThreats: true,
  drlAutoDecisions: true,
  confidenceThreshold: 85,
  emailAlerts: true,
  slackIntegration: false,
}

describe('settingsStore', () => {
  beforeEach(() => {
    useSettingsStore.getState().reset()
  })

  describe('initial state', () => {
    it('has correct default organization name', () => {
      expect(useSettingsStore.getState().organizationName).toBe('SENTINEL Security')
    })

    it('has correct default timezone', () => {
      expect(useSettingsStore.getState().timezone).toBe('UTC')
    })

    it('has autoBlockHighThreats enabled by default', () => {
      expect(useSettingsStore.getState().autoBlockHighThreats).toBe(true)
    })

    it('has drlAutoDecisions enabled by default', () => {
      expect(useSettingsStore.getState().drlAutoDecisions).toBe(true)
    })

    it('has correct default confidence threshold', () => {
      expect(useSettingsStore.getState().confidenceThreshold).toBe(85)
    })

    it('has emailAlerts enabled by default', () => {
      expect(useSettingsStore.getState().emailAlerts).toBe(true)
    })

    it('has slackIntegration disabled by default', () => {
      expect(useSettingsStore.getState().slackIntegration).toBe(false)
    })

    it('matches full default settings object', () => {
      const state = useSettingsStore.getState()
      for (const [key, value] of Object.entries(defaults)) {
        expect(state[key as keyof PlatformSettings]).toBe(value)
      }
    })
  })

  describe('individual setters', () => {
    it('setOrganizationName updates the value', () => {
      useSettingsStore.getState().setOrganizationName('Acme Corp')
      expect(useSettingsStore.getState().organizationName).toBe('Acme Corp')
    })

    it('setTimezone updates the value', () => {
      useSettingsStore.getState().setTimezone('America/New_York')
      expect(useSettingsStore.getState().timezone).toBe('America/New_York')
    })

    it('setAutoBlockHighThreats toggles the flag', () => {
      useSettingsStore.getState().setAutoBlockHighThreats(false)
      expect(useSettingsStore.getState().autoBlockHighThreats).toBe(false)
    })

    it('setDrlAutoDecisions toggles the flag', () => {
      useSettingsStore.getState().setDrlAutoDecisions(false)
      expect(useSettingsStore.getState().drlAutoDecisions).toBe(false)
    })

    it('setConfidenceThreshold updates the value', () => {
      useSettingsStore.getState().setConfidenceThreshold(95)
      expect(useSettingsStore.getState().confidenceThreshold).toBe(95)
    })

    it('setEmailAlerts toggles the flag', () => {
      useSettingsStore.getState().setEmailAlerts(false)
      expect(useSettingsStore.getState().emailAlerts).toBe(false)
    })

    it('setSlackIntegration toggles the flag', () => {
      useSettingsStore.getState().setSlackIntegration(true)
      expect(useSettingsStore.getState().slackIntegration).toBe(true)
    })
  })

  describe('setAll', () => {
    it('merges a partial update into settings', () => {
      useSettingsStore.getState().setAll({
        organizationName: 'MegaCorp',
        confidenceThreshold: 50,
      })

      const state = useSettingsStore.getState()
      expect(state.organizationName).toBe('MegaCorp')
      expect(state.confidenceThreshold).toBe(50)
      expect(state.timezone).toBe('UTC')
    })

    it('can update all settings at once', () => {
      const full: PlatformSettings = {
        organizationName: 'Full Override',
        timezone: 'Europe/London',
        autoBlockHighThreats: false,
        drlAutoDecisions: false,
        confidenceThreshold: 10,
        emailAlerts: false,
        slackIntegration: true,
      }

      useSettingsStore.getState().setAll(full)

      const state = useSettingsStore.getState()
      for (const [key, value] of Object.entries(full)) {
        expect(state[key as keyof PlatformSettings]).toBe(value)
      }
    })
  })

  describe('reset', () => {
    it('restores all defaults after modifications', () => {
      useSettingsStore.getState().setOrganizationName('Modified')
      useSettingsStore.getState().setConfidenceThreshold(10)
      useSettingsStore.getState().setSlackIntegration(true)
      useSettingsStore.getState().setAutoBlockHighThreats(false)

      useSettingsStore.getState().reset()

      const state = useSettingsStore.getState()
      for (const [key, value] of Object.entries(defaults)) {
        expect(state[key as keyof PlatformSettings]).toBe(value)
      }
    })
  })

  describe('persistence', () => {
    it('store is created with persist middleware (name: sentinel-settings)', () => {
      const store = useSettingsStore as unknown as { persist: { getOptions: () => { name: string } } }
      expect(store.persist.getOptions().name).toBe('sentinel-settings')
    })
  })

  describe('independence of setters', () => {
    it('changing one setting does not affect others', () => {
      useSettingsStore.getState().setOrganizationName('NewOrg')
      useSettingsStore.getState().setConfidenceThreshold(42)

      const state = useSettingsStore.getState()
      expect(state.organizationName).toBe('NewOrg')
      expect(state.confidenceThreshold).toBe(42)
      expect(state.timezone).toBe('UTC')
      expect(state.autoBlockHighThreats).toBe(true)
      expect(state.emailAlerts).toBe(true)
      expect(state.slackIntegration).toBe(false)
    })
  })
})
