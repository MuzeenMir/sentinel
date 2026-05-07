/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        sentinel: {
          950: '#060a14',
          900: '#0a0e1a',
          800: '#111827',
          700: '#1e293b',
          600: '#334155',
          500: '#475569',
          accent: '#06b6d4',
          'accent-light': '#22d3ee',
          danger: '#ef4444',
          'danger-dark': '#dc2626',
          warning: '#f59e0b',
          success: '#10b981',
          info: '#3b82f6',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
