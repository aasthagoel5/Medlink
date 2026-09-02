import { useEffect, useRef } from "react";
import { Link, useNavigate } from "react-router";
import { MedlinkLogo } from "../components/Logo";

// ── Animated pulse-line — draws once on mount, then a blinking cursor ──────────

function PulseLine() {
  const pathRef = useRef(null);

  useEffect(() => {
    const path = pathRef.current;
    if (!path) return;
    const len = path.getTotalLength();
    path.style.strokeDasharray = `${len}`;
    path.style.strokeDashoffset = `${len}`;
    path.getBoundingClientRect(); // force reflow before transition
    path.style.transition = "stroke-dashoffset 2s ease-out 0.5s";
    path.style.strokeDashoffset = "0";
  }, []);

  return (
    <svg
      viewBox="0 0 520 180"
      fill="none"
      className="w-full"
      aria-hidden="true"
    >
      {/* Baseline */}
      <line
        x1="0"
        y1="90"
        x2="520"
        y2="90"
        stroke="#BAE6FD"
        strokeWidth="1.5"
      />

      {/* EKG trace: flat → P wave → QRS complex → T wave → flat */}
      <path
        ref={pathRef}
        d="M0 90 L155 90 L163 82 L170 60 L176 82 L180 90 L185 100 L189 15 L193 152 L198 90 L205 70 L216 90 L520 90"
        stroke="#0891B2"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />

      {/* Blinking cursor — fades in after trace finishes */}
      <circle cx="520" cy="90" r="4.5" fill="#0891B2">
        <animate
          attributeName="opacity"
          values="0;0;1;0.85;0.2;0.85"
          dur="2s"
          repeatCount="indefinite"
          begin="2.6s"
        />
      </circle>
    </svg>
  );
}

// ── Page data ────────────────────────────────────────────────────────────────

const WHY_POINTS = [
  {
    stripe: "#0891B2",
    title: "Stop repeating yourself.",
    body: "New doctor, same questions. MEDLINK holds your complete history so you never have to reconstruct it from memory again.",
  },
  {
    stripe: "#0D9488",
    title: "Critical access in an emergency.",
    body: "Allergies, medications, conditions — available to emergency responders in seconds, even when you cannot speak for yourself.",
  },
  {
    stripe: "#94A3B8",
    title: "You control who sees what.",
    body: "Send specific records, set an expiry, revoke access at any time. No hospital system decides who sees your data — you do.",
  },
];

const STEPS = [
  {
    n: "1",
    title: "Upload",
    body: "Add records from any provider — PDFs, lab results, scanned documents. Clinics can forward directly to your account.",
  },
  {
    n: "2",
    title: "Organise",
    body: "MEDLINK sorts automatically by date, type, and provider. Search everything in seconds.",
  },
  {
    n: "3",
    title: "Share",
    body: "Send a specific record or your full profile to any provider. Set an access window and revoke it whenever you choose.",
  },
];

// ── Home page ────────────────────────────────────────────────────────────────

export default function Home() {
  const navigate = useNavigate();

  return (
    <div className="bg-[#F0F9FF]">
      {/* ── Nav ── */}
      <nav className="sticky top-0 z-50 bg-[#F0F9FF]/95 backdrop-blur-md border-b border-sky-200">
        <div className="max-w-6xl mx-auto px-8 h-16 flex items-center justify-between">
          <Link to="/">
            <MedlinkLogo size={34} showName />
          </Link>

          <div className="hidden md:flex items-center gap-8">
            <a
              href="#how-it-works"
              className="text-sm text-slate-600 hover:text-[#0891B2] transition-colors"
            >
              How it works
            </a>
            <a
              href="#security"
              className="text-sm text-slate-600 hover:text-[#0891B2] transition-colors"
            >
              Security
            </a>
            <Link
              to="/auth"
              className="text-sm text-slate-600 hover:text-[#0891B2] transition-colors"
            >
              Log in
            </Link>
          </div>

          <Link
            to="/auth"
            state={{ tab: "signup" }}
            className="px-4 py-2 text-sm font-semibold text-white rounded-lg hover:opacity-90 transition-opacity"
            style={{ background: "linear-gradient(135deg, #22D3EE, #0891B2)" }}
          >
            Get Started
          </Link>
        </div>
      </nav>

      {/* ── Hero ── */}
      <section className="max-w-6xl mx-auto px-8 py-20 lg:py-28 grid grid-cols-1 lg:grid-cols-[1fr_1.1fr] gap-12 lg:gap-16 items-center">
        {/* Left: text */}
        <div>
          <h1 className="font-display text-[3.4rem] lg:text-[4.5rem] font-bold leading-[1.06] tracking-tight text-[#0F172A] mb-6">
            Your health story,
            <br />
            in one place.
          </h1>
          <p className="text-slate-600 text-lg leading-relaxed mb-9 max-w-[22rem]">
            MEDLINK keeps your medical records private, complete, and always
            accessible — on your terms.
          </p>
          <button
            onClick={() => navigate("/auth", { state: { tab: "signup" } })}
            className="px-6 py-3.5 text-sm font-semibold text-white rounded-xl hover:opacity-90 active:opacity-80 transition-opacity shadow-[0_4px_20px_rgba(8,145,178,0.3)]"
            style={{
              background: "linear-gradient(135deg, #22D3EE 0%, #0891B2 100%)",
            }}
          >
            Get started — it's free
          </button>
        </div>

        {/* Right: one animation, nothing else */}
        <div className="flex items-center">
          <PulseLine />
        </div>
      </section>

      {/* ── Why MEDLINK ── */}
      <section className="max-w-6xl mx-auto px-8 py-20 border-t border-sky-200/70">
        <h2 className="font-display text-3xl font-bold text-[#0F172A] mb-12">
          Why MEDLINK
        </h2>
        <div className="flex flex-col md:flex-row gap-10 md:gap-12">
          {WHY_POINTS.map(({ stripe, title, body }) => (
            <div
              key={title}
              className="flex-1 pl-5"
              style={{ borderLeft: `3px solid ${stripe}` }}
            >
              <h3 className="font-display text-lg font-semibold text-[#0F172A] mb-2">
                {title}
              </h3>
              <p className="text-slate-600 text-sm leading-relaxed">{body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── How it works ── */}
      <section
        id="how-it-works"
        className="max-w-6xl mx-auto px-8 py-20 border-t border-sky-200/70"
      >
        <h2 className="font-display text-3xl font-bold text-[#0F172A] mb-12">
          How it works
        </h2>

        {/* Desktop: horizontal with connector */}
        <div className="hidden md:flex items-start">
          {STEPS.flatMap((step, i) => [
            ...(i > 0
              ? [
                  <div
                    key={`sep-${i}`}
                    className="flex-shrink-0 w-14 pt-5 flex items-center"
                  >
                    <div className="h-px w-full bg-[#BAE6FD]" />
                  </div>,
                ]
              : []),
            <div key={step.n} className="flex-1">
              <div className="w-10 h-10 rounded-full bg-white border-2 border-[#0891B2] text-[#0891B2] text-sm font-bold flex items-center justify-center mb-5">
                {step.n}
              </div>
              <h3 className="font-display text-xl font-semibold text-[#0F172A] mb-2">
                {step.title}
              </h3>
              <p className="text-slate-600 text-sm leading-relaxed">
                {step.body}
              </p>
            </div>,
          ])}
        </div>

        {/* Mobile: vertical */}
        <div className="md:hidden flex flex-col gap-8">
          {STEPS.map((step) => (
            <div key={step.n} className="flex gap-4 items-start">
              <div className="w-10 h-10 rounded-full bg-white border-2 border-[#0891B2] text-[#0891B2] text-sm font-bold flex items-center justify-center flex-shrink-0">
                {step.n}
              </div>
              <div>
                <h3 className="font-display text-lg font-semibold text-[#0F172A] mb-1">
                  {step.title}
                </h3>
                <p className="text-slate-600 text-sm leading-relaxed">
                  {step.body}
                </p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Security ── */}
      <section
        id="security"
        className="max-w-6xl mx-auto px-8 py-20 border-t border-sky-200/70"
      >
        <h2 className="font-display text-3xl font-bold text-[#0F172A] mb-8">
          Security you can verify.
        </h2>
        <div className="max-w-2xl space-y-5 text-slate-600 text-base leading-relaxed">
          <p>
            Your records are encrypted at rest with AES-256 and in transit over
            TLS 1.3. Records you share are end-to-end encrypted — MEDLINK's
            servers cannot read their contents. Only you and the recipient can.
          </p>
          <p>
            Sharing is always explicit and time-limited. You choose exactly what
            a provider can see and for how long. You can revoke access before
            the window closes. A complete log of every access event is available
            to you at any time in your account.
          </p>
          <p>
            We do not sell your data, run ads, or share your information with
            insurers, pharmaceutical companies, or any third party. These are
            commitments written into our terms — not marketing language.
          </p>
        </div>
      </section>

      {/* ── Final CTA ── */}
      <section className="max-w-6xl mx-auto px-8 py-20 border-t border-sky-200/70">
        <h2 className="font-display text-4xl font-bold text-[#0F172A] mb-3 leading-tight">
          Keep your health story
          <br />
          with you.
        </h2>
        <p className="text-slate-500 text-base mb-8">
          Free to start. No credit card required.
        </p>
        <button
          onClick={() => navigate("/auth", { state: { tab: "signup" } })}
          className="px-6 py-3.5 text-sm font-semibold text-white rounded-xl hover:opacity-90 active:opacity-80 transition-opacity shadow-[0_4px_20px_rgba(8,145,178,0.3)]"
          style={{
            background: "linear-gradient(135deg, #22D3EE 0%, #0891B2 100%)",
          }}
        >
          Get started — it's free
        </button>
      </section>

      {/* ── Footer ── */}
      <footer className="border-t border-sky-200">
        <div className="max-w-6xl mx-auto px-8 py-8 flex flex-col md:flex-row items-center justify-between gap-4">
          <MedlinkLogo size={30} showName />
          <div className="flex gap-6">
            {["Privacy", "Terms", "Security", "Contact"].map((l) => (
              <a
                key={l}
                href="#"
                className="text-sm text-slate-500 hover:text-slate-800 transition-colors"
              >
                {l}
              </a>
            ))}
          </div>
          <p className="text-sm text-slate-400">© 2026 MEDLINK</p>
        </div>
      </footer>
    </div>
  );
}
