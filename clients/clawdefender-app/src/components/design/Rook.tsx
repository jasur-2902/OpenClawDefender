import React from "react";

export interface RookProps {
  size?: number;
  color?: string;
}

export const Rook: React.FC<RookProps> = ({ size = 18, color = "currentColor" }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 45 45"
    fill={color}
    aria-hidden="true"
    style={{ display: "block" }}
  >
    <path d="M9 36h27v-3H9zM12 33v-3h21v3zM11 14V8h4v3h4V8h7v3h4V8h4v6l-3 3v9H14l-3-3z" />
    <path d="M14 17h17v9H14z" opacity="0.92" />
  </svg>
);
