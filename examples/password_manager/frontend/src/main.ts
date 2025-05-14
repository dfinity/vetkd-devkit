// Required to run `npm run dev`.
if (!window.global) {
    window.global = window;
}

import "./app.css";
import App from "./App.svelte";

const app = new App({
    target: document.body,
});

export default app;
