/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: '#FFFFFF',
          secondary: '#F9FAFB',
          tertiary: '#F1F4F8',
          hover: '#F1F5F9',
          selected: '#EAF1FF',
        },
        brand: {
          DEFAULT: '#2563D9',
          hover: '#1D4FC4',
          soft: '#E8F0FF',
        },
        critical: '#B42318',
        high: '#A75A05',
        medium: '#D97706',
        low: '#2563D9',
        info: '#245FC4',
        success: '#137A45',
        warning: '#A75A05',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      borderRadius: {
        sm: '7px',
        md: '9px',
        lg: '12px',
      },
    },
  },
  plugins: [],
};
