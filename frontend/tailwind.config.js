/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          800: '#111827',
          900: '#0b1120',
          950: '#070b14',
        },
        slate: {
          850: '#151e2e',
        }
      }
    },
  },
  plugins: [],
}
