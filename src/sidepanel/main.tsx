import React from "react";
import { createRoot } from "react-dom/client";
import { ErrorBoundary } from "../panel/ErrorBoundary";
import { App } from "../panel/App";

createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App mode="sidepanel" />
    </ErrorBoundary>
  </React.StrictMode>
);
