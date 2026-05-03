import React from "react";
import { Icon, Btn } from "./design";

export interface ScanErrorStateProps {
  onRetry: () => void;
  errorMessage?: string;
}

export const ScanErrorState: React.FC<ScanErrorStateProps> = ({ onRetry, errorMessage }) => (
  <div
    style={{
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      padding: "60px 0",
      textAlign: "center",
    }}
  >
    <Icon name="alert" size={40} color="var(--amber)" />
    <h2 style={{ fontSize: 15, fontWeight: 600, color: "var(--ink-0)", marginTop: 16, marginBottom: 4 }}>
      Scan could not complete
    </h2>
    <p style={{ fontSize: 12.5, color: "var(--ink-2)", maxWidth: 400 }}>
      {errorMessage ||
        "RookBot needs file access permission to read AI tool config files. Open System Settings > Privacy & Security > Full Disk Access and make sure RookBot is enabled."}
    </p>
    <Btn kind="primary" onClick={onRetry} style={{ marginTop: 16 }}>
      Try again
    </Btn>
  </div>
);
