import { useState } from "react";
import { createShareLink } from "../lib/sharingApi";

export default function ShareModal({ recordId, onClose }) {
  const [expiry, setExpiry] = useState("1d");
  const [shareUrl, setShareUrl] = useState(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");

  const handleGenerate = async () => {
    setLoading(true);
    setError("");
    try {
      const data = await createShareLink({ recordId, expiry });
      setShareUrl(data.shareUrl);
    } catch (err) {
      setError(err.response?.data?.message || "Failed to create share link");
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(shareUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 px-4"
      onClick={onClose}
    >
      <div
        className="bg-white rounded-2xl p-6 w-full max-w-sm"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display text-lg font-semibold text-[#0F172A]">
            Share record
          </h3>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600"
          >
            ✕
          </button>
        </div>

        {error && (
          <div className="mb-4 px-3 py-2 rounded-lg bg-red-50 border border-red-100 text-sm text-red-600">
            {error}
          </div>
        )}

        {!shareUrl ? (
          <>
            <label className="text-sm font-medium text-slate-600 mb-2 block">
              Link expires in
            </label>
            <div className="flex gap-2 mb-6">
              {[
                { value: "1h", label: "1 hour" },
                { value: "1d", label: "1 day" },
                { value: "7d", label: "7 days" },
              ].map((opt) => (
                <button
                  key={opt.value}
                  onClick={() => setExpiry(opt.value)}
                  className={`flex-1 py-2 text-sm font-medium rounded-lg transition-colors ${
                    expiry === opt.value
                      ? "bg-[#0891B2] text-white"
                      : "bg-[#F0FDFF] text-slate-500 border border-[#E5F0F6]"
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
            <button
              onClick={handleGenerate}
              disabled={loading}
              className="w-full py-2.5 text-sm font-semibold text-white rounded-xl disabled:opacity-50"
              style={{
                background: "linear-gradient(135deg, #22D3EE, #0891B2)",
              }}
            >
              {loading ? "Generating..." : "Generate share link"}
            </button>
          </>
        ) : (
          <>
            <p className="text-xs text-slate-500 mb-2">
              Anyone with this link can view the record until it expires — no
              login required.
            </p>
            <div className="flex items-center gap-2 mb-4">
              <input
                readOnly
                value={shareUrl}
                className="flex-1 px-3 py-2 text-xs bg-[#F8FBFE] border border-[#C8E4F0] rounded-lg text-slate-600"
              />
              <button
                onClick={handleCopy}
                className="px-3 py-2 text-xs font-semibold text-[#0891B2] bg-[#F0FDFF] border border-[#C8E4F0] rounded-lg whitespace-nowrap hover:bg-[#E0FBFF]"
              >
                {copied ? "Copied!" : "Copy"}
              </button>
            </div>
            <button
              onClick={onClose}
              className="w-full py-2.5 text-sm font-medium text-slate-500 border border-[#E5F0F6] rounded-xl hover:bg-slate-50"
            >
              Done
            </button>
          </>
        )}
      </div>
    </div>
  );
}
