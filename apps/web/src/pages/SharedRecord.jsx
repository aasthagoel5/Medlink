import { useEffect, useState } from "react";
import { useParams } from "react-router";
import apiClient from "../lib/apiClient";
import { MedlinkLogo } from "../components/Logo";

const TYPE_LABELS = {
  prescription: "Prescription",
  lab_report: "Lab Report",
  scan: "Scan",
  vaccination: "Vaccination",
  other: "Other",
};

function useCountdown(expiresAt) {
  const [timeLeft, setTimeLeft] = useState("");

  useEffect(() => {
    const interval = setInterval(() => {
      const diff = new Date(expiresAt) - new Date();
      if (diff <= 0) {
        setTimeLeft("Expired");
        clearInterval(interval);
        return;
      }
      const hours = Math.floor(diff / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((diff % (1000 * 60)) / 1000);
      setTimeLeft(
        hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m ${seconds}s`,
      );
    }, 1000);
    return () => clearInterval(interval);
  }, [expiresAt]);

  return timeLeft;
}

export default function SharedRecord() {
  const { token } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    apiClient
      .get(`/sharing/${token}`)
      .then((res) => setData(res.data))
      .catch((err) => {
        if (err.response?.status === 410) setError("This link has expired.");
        else setError("This link is invalid or no longer available.");
      })
      .finally(() => setLoading(false));
  }, [token]);

  const timeLeft = useCountdown(data?.expiresAt);
  const record = data?.record;
  const isImage = record?.fileUrl?.match(/\.(jpg|jpeg|png|gif)$/i);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#F8FBFE]">
        <p className="text-slate-400">Loading...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-[#F8FBFE] px-4">
        <MedlinkLogo size={36} showName />
        <p className="text-slate-500 mt-6">{error}</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F8FBFE] flex flex-col items-center py-10 px-4">
      <MedlinkLogo size={32} showName />

      <div className="w-full max-w-2xl mt-8">
        <div
          className={`mb-4 px-4 py-2.5 rounded-xl text-center text-sm font-medium ${
            timeLeft === "Expired"
              ? "bg-red-50 text-red-600"
              : "bg-[#F0FDFF] text-[#0891B2]"
          }`}
        >
          {timeLeft === "Expired"
            ? "This link has expired"
            : `Link expires in ${timeLeft}`}
        </div>

        <div className="bg-white rounded-2xl border border-[#E5F0F6] overflow-hidden mb-4">
          {isImage ? (
            <img
              src={record.fileUrl}
              alt="Shared record"
              className="w-full h-auto"
            />
          ) : (
            <div className="p-10 text-center">
              <a
                href={record.fileUrl}
                target="_blank"
                rel="noreferrer"
                className="text-sm text-[#0891B2] hover:underline"
              >
                Open document →
              </a>
            </div>
          )}
        </div>

        <div className="bg-white rounded-2xl border border-[#E5F0F6] p-5">
          <span className="text-xs font-semibold text-[#0891B2] uppercase tracking-wide">
            {TYPE_LABELS[record.type] || record.type}
          </span>
          <p className="text-sm text-slate-600 mt-2">
            {record.doctorName && (
              <>
                Provider: {record.doctorName}
                <br />
              </>
            )}
            {record.recordDate &&
              `Date: ${new Date(record.recordDate).toLocaleDateString()}`}
          </p>
        </div>

        <p className="text-center text-xs text-slate-400 mt-6">
          Shared securely via MEDLINK — view only, no login required.
        </p>
      </div>
    </div>
  );
}
