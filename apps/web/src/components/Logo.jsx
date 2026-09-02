import { useId } from "react";

export function MedlinkLogo({ size = 40, showName = true, light = false }) {
  const uid = useId();
  const gradId = `ml${uid.replace(/[^a-z0-9]/gi, "")}`;

  return (
    <div className="inline-flex item-center gap-2.5 select-none">
      <svg
        width={size}
        height={size}
        viewBox="0  0 40 40"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <rect
            width="40"
            height="40"
            rx="11"
            fill={light ? "rgba(255,255,255,0.2)" : `url(#${gradId})`}
          />
          <path
            d="M4 20 L13 20 L15 23.5 L17 10 L19 26 L21 20 L23 16.5 L25 20 L36 20"
            stroke="white"
            strokeWidth="2.3"
            strokeLinecap="round"
            strokeLinejoin="round"
            fill="none"
          />
        </defs>
      </svg>
      {showName && (
        <span
          className="font-bold tracking-[0.13em] uppercase leading-none"
          style={
            light
              ? { color: "white", fontSize: Math.round(size * 0.48) }
              : {
                  fontSize: Math.round(size * 0.48),
                  background:
                    "linear-gradient(135deg, #0891B2 0%, #0D9488 100%)",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  backgroundClip: "text",
                }
          }
        >
          MEDLINK
        </span>
      )}
    </div>
  );
}
