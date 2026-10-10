import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';
import vercel from '@astrojs/vercel';

export default defineConfig({
  output: 'server',
  adapter: vercel(),
  vite: {
    plugins: [tailwindcss()],
  },
  // shortcut: el dominio está hardcodeado en los .astro y en public/robots.txt en vez de
  // leerse de aquí. Cambiar de dominio son ~17 reemplazos. Centralizar cuando cambie dos
  // veces, no antes.
  site: 'https://tbot-dc.vercel.app',
  integrations: [sitemap()],
});
