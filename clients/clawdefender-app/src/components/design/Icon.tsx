import React from "react";

export interface IconProps {
  name: string;
  size?: number;
  stroke?: number;
  color?: string;
}

export const Icon: React.FC<IconProps> = ({
  name,
  size = 18,
  stroke: sw = 1.6,
  color = "currentColor",
}) => {
  const props: React.SVGProps<SVGSVGElement> = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: color,
    strokeWidth: sw,
    strokeLinecap: "round",
    strokeLinejoin: "round",
  };

  switch (name) {
    case "home":
      return <svg {...props}><path d="M3 11l9-7 9 7" /><path d="M5 10v9h14v-9" /></svg>;
    case "activity":
      return <svg {...props}><path d="M3 12h4l3-8 4 16 3-8h4" /></svg>;
    case "alert":
      return <svg {...props}><path d="M12 3l9 16H3z" /><path d="M12 10v4" /><circle cx="12" cy="17" r=".7" fill={color} /></svg>;
    case "scan":
      return <svg {...props}><circle cx="11" cy="11" r="6" /><path d="M16 16l5 5" /></svg>;
    case "chat":
      return <svg {...props}><path d="M4 5h16v11H9l-5 4z" /></svg>;
    case "tools":
      return (
        <svg {...props}>
          <rect x="3" y="3" width="7" height="7" rx="1.5" />
          <rect x="14" y="3" width="7" height="7" rx="1.5" />
          <rect x="3" y="14" width="7" height="7" rx="1.5" />
          <rect x="14" y="14" width="7" height="7" rx="1.5" />
        </svg>
      );
    case "settings":
      return (
        <svg {...props}>
          <circle cx="12" cy="12" r="3" />
          <path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" />
        </svg>
      );
    case "audit":
      return <svg {...props}><path d="M5 3h11l4 4v14H5z" /><path d="M9 12h7M9 16h7M9 8h4" /></svg>;
    case "sparkles":
      return <svg {...props}><path d="M12 4v6M12 14v6M4 12h6M14 12h6" /></svg>;
    case "lightning":
      return <svg {...props}><path d="M13 3L4 14h6l-1 7 9-11h-6z" /></svg>;
    case "shield":
      return <svg {...props}><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /></svg>;
    case "process":
      return (
        <svg {...props}>
          <rect x="4" y="6" width="16" height="3" rx="1" />
          <rect x="4" y="11" width="10" height="3" rx="1" />
          <rect x="4" y="16" width="13" height="3" rx="1" />
        </svg>
      );
    case "network":
      return (
        <svg {...props}>
          <circle cx="12" cy="6" r="2.5" />
          <circle cx="5" cy="18" r="2.5" />
          <circle cx="19" cy="18" r="2.5" />
          <path d="M12 8.5l-7 7M12 8.5l7 7" />
        </svg>
      );
    case "dns":
      return <svg {...props}><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18" /></svg>;
    case "wrench":
      return <svg {...props}><path d="M14 6a4 4 0 105 5l4 4-3 3-4-4a4 4 0 01-5-5z" /></svg>;
    case "search":
      return <svg {...props}><circle cx="11" cy="11" r="6" /><path d="M16 16l5 5" /></svg>;
    case "send":
      return <svg {...props}><path d="M3 12L21 4l-7 17-2-7z" /></svg>;
    case "chevron":
      return <svg {...props}><path d="M9 6l6 6-6 6" /></svg>;
    case "x":
      return <svg {...props}><path d="M5 5l14 14M19 5L5 19" /></svg>;
    case "check":
      return <svg {...props}><path d="M5 12l5 5 9-11" /></svg>;
    case "play":
      return <svg {...props}><path d="M6 4l13 8-13 8z" fill={color} /></svg>;
    case "pause":
      return (
        <svg {...props}>
          <rect x="6" y="4" width="4" height="16" />
          <rect x="14" y="4" width="4" height="16" />
        </svg>
      );
    case "filter":
      return <svg {...props}><path d="M3 5h18l-7 9v6l-4-2v-4z" /></svg>;
    case "refresh":
      return <svg {...props}><path d="M4 12a8 8 0 0114-5l3 3M3 17l3-3a8 8 0 0014-5" /></svg>;
    case "download":
      return <svg {...props}><path d="M12 4v12M6 12l6 6 6-6M4 20h16" /></svg>;
    case "lock":
      return <svg {...props}><rect x="5" y="11" width="14" height="9" rx="1.5" /><path d="M8 11V7a4 4 0 018 0v4" /></svg>;
    case "cpu":
      return (
        <svg {...props}>
          <rect x="6" y="6" width="12" height="12" rx="1.5" />
          <rect x="9" y="9" width="6" height="6" rx="1" />
          <path d="M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3" />
        </svg>
      );
    case "cloud":
      return <svg {...props}><path d="M7 18a4 4 0 010-8 5 5 0 019.6-1.5A4 4 0 0117 18z" /></svg>;
    case "key":
      return <svg {...props}><circle cx="8" cy="15" r="3" /><path d="M11 13l9-9M16 8l3 3" /></svg>;
    case "history":
      return <svg {...props}><path d="M3 12a9 9 0 109-9 9 9 0 00-7 3.5" /><path d="M3 4v4h4" /><path d="M12 7v5l3 2" /></svg>;
    case "sidebar":
      return <svg {...props}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M9 4v16" /></svg>;
    case "eye":
      return <svg {...props}><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z" /><circle cx="12" cy="12" r="3" /></svg>;
    default:
      return <svg {...props}><circle cx="12" cy="12" r="3" /></svg>;
  }
};
