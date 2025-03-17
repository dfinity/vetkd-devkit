// @ts-check

import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
    {
        files: ["src/**/*.ts"],
        extends: [
            eslint.configs.recommended,
            tseslint.configs.recommended,
        ],
        ignores: ["**/declarations/"]
    }
);
