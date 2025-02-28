import { defineConfig } from 'vitest/config'
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

export default defineConfig({
    plugins: [
        wasm(),
        topLevelAwait()
    ],
    test: {
        environment: "happy-dom",
        setupFiles: ['test/setup.ts'],
        testTimeout: 60000
    }
});