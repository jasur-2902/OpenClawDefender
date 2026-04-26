import React from "react";
import { Icon } from "./Icon";

type BtnKind = "primary" | "ghost" | "soft" | "danger" | "accent";
type BtnSize = "sm" | "md" | "lg";

export interface BtnProps {
  children?: React.ReactNode;
  kind?: BtnKind;
  size?: BtnSize;
  icon?: string;
  onClick?: React.MouseEventHandler<HTMLButtonElement>;
  style?: React.CSSProperties;
  disabled?: boolean;
}

const sizes: Record<BtnSize, { p: string; fs: number; r: number }> = {
  sm: { p: "5px 10px", fs: 12, r: 6 },
  md: { p: "7px 14px", fs: 13, r: 7 },
  lg: { p: "10px 18px", fs: 14, r: 8 },
};

const kinds: Record<BtnKind, { bg: string; c: string; b: string; sh: string }> = {
  primary: {
    bg: "var(--accent)",
    c: "white",
    b: "var(--accent)",
    sh: "0 1px 2px oklch(0 0 0 / 0.10), inset 0 1px 0 oklch(1 0 0 / 0.20)",
  },
  ghost: { bg: "transparent", c: "var(--ink-1)", b: "transparent", sh: "none" },
  soft: { bg: "var(--bg-2)", c: "var(--ink-0)", b: "var(--line)", sh: "none" },
  danger: {
    bg: "var(--red)",
    c: "white",
    b: "var(--red)",
    sh: "0 1px 2px oklch(0 0 0 / 0.10), inset 0 1px 0 oklch(1 0 0 / 0.20)",
  },
  accent: { bg: "var(--accent-soft)", c: "var(--accent)", b: "transparent", sh: "none" },
};

export const Btn: React.FC<BtnProps> = ({
  children,
  kind = "ghost",
  size = "md",
  icon,
  onClick,
  style,
  disabled,
}) => {
  const s = sizes[size];
  const k = kinds[kind];
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: s.p,
        fontSize: s.fs,
        fontWeight: 500,
        background: k.bg,
        color: k.c,
        border: `1px solid ${k.b}`,
        borderRadius: s.r,
        boxShadow: k.sh,
        opacity: disabled ? 0.4 : 1,
        cursor: disabled ? "not-allowed" : "pointer",
        transition: "transform 0.08s ease, filter 0.15s ease",
        ...style,
      }}
      onMouseDown={(e) => {
        if (!disabled) e.currentTarget.style.transform = "scale(0.98)";
      }}
      onMouseUp={(e) => {
        e.currentTarget.style.transform = "";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform = "";
      }}
    >
      {icon && <Icon name={icon} size={13.5} />}
      {children}
    </button>
  );
};
