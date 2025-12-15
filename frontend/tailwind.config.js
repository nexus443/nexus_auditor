/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./*.{js,ts,jsx,tsx}", // On cherche les fichiers à la racine
    "./src/**/*.{js,ts,jsx,tsx}", // Et dans src si jamais
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}