# Threat — landing

Web pública del bot (`tbot-dc.vercel.app`). Astro 6 + Tailwind 4, SSR en Vercel.

```sh
pnpm install
pnpm run dev
pnpm run build
```

`pnpm add <pkg>` lleva `-w` porque hay `pnpm-workspace.yaml`. En Windows `pnpm build`
falla al empaquetar para Vercel con un EPERM de symlinks; Vercel construye en Linux y
funciona.
