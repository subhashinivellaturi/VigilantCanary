import React from "react";
import ReactDOM from "react-dom/client";
import App from "./AppShell";
import "./styles.css";

// Suppress Recharts defaultProps warnings and E.C.P warnings
if (typeof window !== "undefined") {
  const originalError = console.error;
  console.error = (...args: any[]) => {
    if (
      typeof args[0] === "string" &&
      (args[0].includes("defaultProps will be removed") ||
        args[0].includes("E.C.P is not enabled"))
    ) {
      return;
    }
    originalError.call(console, ...args);
  };
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
