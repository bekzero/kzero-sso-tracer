import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "../panel/App";

createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App mode="sidepanel" />
  </React.StrictMode>
);
