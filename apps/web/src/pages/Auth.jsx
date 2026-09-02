import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router";
import { MedlinkLogo } from "../components/Logo";
import { login, signup } from "../lib/authApi";

function EyeIcon({ visible }) {
  return visible ? (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  ) : (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
      <line x1="1" y1="1" x2="23" y2="23" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function ShieldIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function Field({
  id,
  label,
  type = "text",
  placeholder,
  autoComplete,
  labelAction,
  value,
  onChange,
}) {
  const [showPw, setShowPw] = useState(false);
  const isPassword = type === "password";

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between min-h-5">
        <label
          htmlFor={id}
          className="text-sm font-medium text-slate-600 leading-none"
        >
          {label}
        </label>
        {labelAction}
      </div>
      <div className="relative">
        <input
          id={id}
          name={id}
          type={isPassword && showPw ? "text" : type}
          placeholder={placeholder}
          autoComplete={autoComplete}
          value={value}
          onChange={onChange}
          className="w-full px-3.5 py-2.5 text-sm text-slate-700 bg-[#F8FBFE] border border-[#C8E4F0]
                     rounded-xl placeholder:text-slate-400 transition-all duration-150
                     focus:outline-none focus:bg-white focus:border-[#0891B2] focus:ring-2 focus:ring-[#0891B2]/15"
        />
        {isPassword && (
          <button
            type="button"
            onClick={() => setShowPw((v) => !v)}
            tabIndex={-1}
            aria-label={showPw ? "Hide password" : "Show password"}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-[#0891B2] transition-colors"
          >
            <EyeIcon visible={showPw} />
          </button>
        )}
      </div>
    </div>
  );
}

function PrimaryButton({ children, disabled }) {
  return (
    <button
      type="submit"
      disabled={disabled}
      style={{
        background: "linear-gradient(135deg, #22D3EE 0%, #0891B2 100%)",
      }}
      className="w-full py-2.5 px-4 text-white text-sm font-semibold rounded-xl mt-1
                 hover:opacity-90 active:opacity-80 transition-opacity disabled:opacity-50
                 focus:outline-none focus:ring-2 focus:ring-[#0891B2]/40 focus:ring-offset-2
                 shadow-[0_4px_16px_rgba(8,145,178,0.25)]"
    >
      {children}
    </button>
  );
}

function LegalText({ action }) {
  return (
    <p className="text-center text-xs text-slate-400 leading-relaxed">
      By {action}, you agree to our{" "}
      <a href="#" className="text-[#0891B2] hover:underline">
        Terms
      </a>{" "}
      and{" "}
      <a href="#" className="text-[#0891B2] hover:underline">
        Privacy Policy
      </a>
    </p>
  );
}

const BENEFITS = [
  "End-to-end encrypted health records",
  "Unified records from all your providers",
  "Accessible 24/7 from any device",
  "One-click verified record sharing",
];

export default function Auth() {
  const location = useLocation();
  const navigate = useNavigate();
  const [tab, setTab] = useState(location.state?.tab ?? "login");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [loginData, setLoginData] = useState({ email: "", password: "" });
  const [signupData, setSignupData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
  });

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const data = await login({
        email: loginData.email,
        password: loginData.password,
      });
      localStorage.setItem("medlink_token", data.token);
      localStorage.setItem("medlink_user", JSON.stringify(data.user));
      navigate("/dashboard"); // we'll build this page next
    } catch (err) {
      setError(
        err.response?.data?.message ||
          "Something went wrong. Please try again.",
      );
    } finally {
      setLoading(false);
    }
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    setError("");

    if (signupData.password !== signupData.confirmPassword) {
      setError("Passwords don't match");
      return;
    }

    setLoading(true);
    try {
      const data = await signup({
        name: signupData.name,
        email: signupData.email,
        password: signupData.password,
      });
      localStorage.setItem("medlink_token", data.token);
      localStorage.setItem("medlink_user", JSON.stringify(data.user));
      navigate("/dashboard");
    } catch (err) {
      setError(
        err.response?.data?.message ||
          "Something went wrong. Please try again.",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col md:grid md:grid-cols-2">
      <div
        className="hidden md:flex flex-col justify-between p-10 relative overflow-hidden"
        style={{
          background:
            "linear-gradient(150deg, #0E7490 0%, #0891B2 60%, #0D9488 100%)",
        }}
      >
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="w-[600px] h-[600px] rounded-full border border-white/10" />
          <div className="absolute w-[430px] h-[430px] rounded-full border border-white/10" />
          <div className="absolute w-[260px] h-[260px] rounded-full border border-white/10" />
        </div>
        <div className="absolute -top-16 -right-16 w-64 h-64 rounded-full bg-white/10 blur-3xl pointer-events-none" />
        <div className="absolute -bottom-16 -left-16 w-64 h-64 rounded-full bg-white/10 blur-3xl pointer-events-none" />

        <div className="relative">
          <button onClick={() => navigate("/")} className="focus:outline-none">
            <MedlinkLogo size={44} showName light />
          </button>
        </div>

        <div className="relative">
          <h2 className="font-display text-3xl font-bold text-white leading-tight mb-3">
            Your health,
            <br />
            in trusted hands.
          </h2>
          <p className="text-white/70 text-sm leading-relaxed mb-8 max-w-xs">
            Secure, unified health records — built around patients, designed for
            the modern care team.
          </p>

          <div className="space-y-3.5">
            {BENEFITS.map((benefit) => (
              <div key={benefit} className="flex items-start gap-3">
                <div className="w-5 h-5 rounded-full bg-white/20 flex items-center justify-center flex-shrink-0 mt-0.5 text-white">
                  <CheckIcon />
                </div>
                <span className="text-white/85 text-sm leading-relaxed">
                  {benefit}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="relative flex flex-wrap gap-4">
          {["Encrypted", "Access Logs", "You Control Sharing"].map((cert) => (
            <div
              key={cert}
              className="flex items-center gap-1.5 bg-white/15 rounded-full px-3 py-1.5"
            >
              <ShieldIcon />
              <span className="text-white/90 text-xs font-medium">{cert}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="flex flex-col items-center justify-center bg-white px-8 py-12 min-h-screen md:min-h-0">
        <div className="md:hidden mb-8">
          <Link to="/">
            <MedlinkLogo size={38} showName />
          </Link>
        </div>

        <div className="w-full max-w-sm">
          <div
            className="bg-white rounded-3xl border border-[#C8E4F0]/70"
            style={{
              boxShadow:
                "0 2px 12px rgba(8,145,178,0.06), 0 14px 48px rgba(8,145,178,0.08)",
            }}
          >
            <div className="flex">
              {["login", "signup"].map((t) => (
                <button
                  key={t}
                  onClick={() => {
                    setTab(t);
                    setError("");
                  }}
                  className={`flex-1 py-4 text-sm font-semibold transition-all duration-150 border-b-2
                    first:rounded-tl-3xl last:rounded-tr-3xl ${
                      tab === t
                        ? "text-[#0891B2] border-[#0891B2] bg-gradient-to-b from-[#F0FDFF] to-white"
                        : "text-slate-400 border-[#E5F0F6] hover:text-slate-600"
                    }`}
                >
                  {t === "login" ? "Login" : "Sign Up"}
                </button>
              ))}
            </div>

            <div className="px-7 py-6">
              {error && (
                <div className="mb-4 px-3 py-2.5 rounded-lg bg-red-50 border border-red-100 text-sm text-red-600">
                  {error}
                </div>
              )}

              {tab === "login" ? (
                <form className="flex flex-col gap-4" onSubmit={handleLogin}>
                  <Field
                    id="login-email"
                    label="Email"
                    type="email"
                    placeholder="you@example.com"
                    autoComplete="email"
                    value={loginData.email}
                    onChange={(e) =>
                      setLoginData({ ...loginData, email: e.target.value })
                    }
                  />
                  <Field
                    id="login-pw"
                    label="Password"
                    type="password"
                    placeholder="Enter your password"
                    autoComplete="current-password"
                    value={loginData.password}
                    onChange={(e) =>
                      setLoginData({ ...loginData, password: e.target.value })
                    }
                    labelAction={
                      <a
                        href="#"
                        className="text-xs text-[#0891B2] hover:text-[#0E7490] font-medium transition-colors leading-none"
                      >
                        Forgot password?
                      </a>
                    }
                  />
                  <PrimaryButton disabled={loading}>
                    {loading ? "Signing in..." : "Sign in to MEDLINK"}
                  </PrimaryButton>
                  <LegalText action="signing in" />
                </form>
              ) : (
                <form className="flex flex-col gap-3.5" onSubmit={handleSignup}>
                  <Field
                    id="su-name"
                    label="Full name"
                    type="text"
                    placeholder="Jane Smith"
                    autoComplete="name"
                    value={signupData.name}
                    onChange={(e) =>
                      setSignupData({ ...signupData, name: e.target.value })
                    }
                  />
                  <Field
                    id="su-email"
                    label="Email"
                    type="email"
                    placeholder="you@example.com"
                    autoComplete="email"
                    value={signupData.email}
                    onChange={(e) =>
                      setSignupData({ ...signupData, email: e.target.value })
                    }
                  />
                  <Field
                    id="su-pw"
                    label="Password"
                    type="password"
                    placeholder="Create a strong password"
                    autoComplete="new-password"
                    value={signupData.password}
                    onChange={(e) =>
                      setSignupData({ ...signupData, password: e.target.value })
                    }
                  />
                  <Field
                    id="su-confirm"
                    label="Confirm password"
                    type="password"
                    placeholder="Re-enter your password"
                    autoComplete="new-password"
                    value={signupData.confirmPassword}
                    onChange={(e) =>
                      setSignupData({
                        ...signupData,
                        confirmPassword: e.target.value,
                      })
                    }
                  />
                  <PrimaryButton disabled={loading}>
                    {loading ? "Creating account..." : "Create your account"}
                  </PrimaryButton>
                  <LegalText action="creating an account" />
                </form>
              )}
            </div>
          </div>

          <div className="mt-5 flex items-center justify-center gap-3 text-xs text-slate-400 flex-wrap">
            <span className="flex items-center gap-1.5">
              <ShieldIcon />
              Encrypted at rest
            </span>
            <span className="text-slate-300">·</span>
            <span>TLS in transit</span>
          </div>
        </div>
      </div>
    </div>
  );
}
