import daisyui from "daisyui";
import lineClamp from "@tailwindcss/line-clamp";

export default {
    content: ["./index.html", "./src/**/*.{svelte,js,ts,jsx,tsx}"],
    plugins: [daisyui, lineClamp],
};
