// Required to run `npm run dev`.
if (!window.global) {
    window.global = window;
}

import "./app.css";
import App from "./App.svelte";

const init = () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const app = new App({
        target: document.body,
    });
};

init();
