import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from 'tailwindcss'
import autoprefixer from "autoprefixer";
import css from 'rollup-plugin-css-only';
import typescript from '@rollup/plugin-typescript';
import environment from 'vite-plugin-environment';

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    svelte(),
    css({ output: "bundle.css" }),
    typescript({
      sourceMap: true,
      inlineSources: true,
    }),
    environment("all", { prefix: "CANISTER_" }),
    environment("all", { prefix: "DFX_" }),
  ],
  css: {
    postcss: {
      plugins: [autoprefixer(), tailwindcss()],
    }
  },
  build: {
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
      sourcemap: true,
    },
  },
  root: "./",
  server: {
    hmr: false
  }
})