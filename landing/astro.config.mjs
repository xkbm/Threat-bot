import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';
import vercel from '@astrojs/vercel';

export default defineConfig({
  vite: {
    plugins: [tailwindcss()],
  },
  output: 'server',
  adapter: vercel(),
  site: 'https://tbot-dc.vercel.app',
  integrations: [sitemap()],
});
