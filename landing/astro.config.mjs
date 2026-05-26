import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  site: 'https://threat-bot.dev',
  vite: {
    plugins: [tailwindcss()],
  },
});
