// @ts-check

import eslint from "@eslint/js";
import eslintPluginPrettierRecommended from "eslint-plugin-prettier/recommended";
import globals from "globals";
import tseslint from "typescript-eslint";
import svelteConfig from "./svelte.config.js";
import svelte from "eslint-plugin-svelte";

export default tseslint.config(
    eslint.configs.recommended,
    tseslint.configs.recommended,
    ...svelte.configs.recommended,
    eslintPluginPrettierRecommended,
    {
        languageOptions: {
            globals: {
                ...globals.browser,
                ...globals.node,
            },
        },
    },
    {
        files: ["**/*.svelte", "**/*.svelte.ts", "**/*.svelte.js"],
        languageOptions: {
            parserOptions: {
                projectService: true,
                extraFileExtensions: [".svelte"],
                parser: tseslint.parser,
                svelteConfig,
            },
        },
    },
    { ignores: ["dist/", "babel.config.js", "src/declarations"] },
);
