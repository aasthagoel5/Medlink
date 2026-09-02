import { useState } from "react";
import { useNavigate } from "react-router";
import { MedlinkLogo } from "../components/Logo";
import { createRecord } from "../lib/recordsApi";

const RECORD_TYPES = [
  { value: "prescription", label: "Prescription" },
  { value: "lab_report", label: "Lab Report" },
  { value: "scan", label: "Scan" },
  { value: "vaccination", label: "Vaccination" },
  { value: "other", label: "Other" },
];

export default function RecordUpload() {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [type, setType] = useState("prescription");
  const [doctorName, setDoctorName] = useState("");
  const [recordDate, setRecordDate] = useState("");
  const [notes, setNotes] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files?.[0]) setFile(e.dataTransfer.files[0]);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    if (!file) {
      setError("Please select a file to upload");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("type", type);
    formData.append("doctorName", doctorName);
    formData.append("recordDate", recordDate);
    formData.append("notes", notes);

    setLoading(true);
    try {
      const record = await createRecord(formData);
      navigate(`/records/${record._id}`);
    } catch (err) {
      setError(
        err.response?.data?.message || "Upload failed. Please try again.",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#F0F9FF]">
      <nav className="sticky top-0 z-50 bg-[#F0F9FF]/95 backdrop-blur-md border-b border-sky-200">
        <div className="max-w-3xl mx-auto px-8 h-16 flex items-center">
          <MedlinkLogo size={34} showName />
        </div>
      </nav>

      <div className="max-w-3xl mx-auto px-8 py-10">
        <button
          onClick={() => navigate("/dashboard")}
          className="text-sm text-slate-500 hover:text-[#0891B2] transition-colors mb-6"
        >
          ← Back to records
        </button>

        <h1 className="font-display text-3xl font-bold text-[#0F172A] mb-8">
          Upload a Record
        </h1>

        {error && (
          <div className="mb-6 px-4 py-3 rounded-xl bg-red-50 border border-red-100 text-sm text-red-600">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="flex flex-col gap-6">
          {/* File drop zone */}
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded-2xl p-10 text-center transition-colors ${
              dragging
                ? "border-[#0891B2] bg-[#F0FDFF]"
                : "border-[#C8E4F0] bg-white"
            }`}
          >
            {file ? (
              <div>
                <p className="text-sm font-medium text-[#0F172A] mb-1">
                  {file.name}
                </p>
                <p className="text-xs text-slate-400 mb-3">
                  {(file.size / 1024).toFixed(0)} KB
                </p>
                <button
                  type="button"
                  onClick={() => setFile(null)}
                  className="text-xs text-[#0891B2] hover:underline"
                >
                  Choose a different file
                </button>
              </div>
            ) : (
              <div>
                <p className="text-sm text-slate-500 mb-3">
                  Drag and drop your file here, or
                </p>
                <label className="inline-block px-4 py-2 text-sm font-semibold text-[#0891B2] bg-[#F0FDFF] border border-[#C8E4F0] rounded-lg cursor-pointer hover:bg-[#E0FBFF] transition-colors">
                  Browse files
                  <input
                    type="file"
                    accept="image/*,.pdf"
                    className="hidden"
                    onChange={(e) => setFile(e.target.files?.[0] || null)}
                  />
                </label>
                <p className="text-xs text-slate-400 mt-3">
                  JPG, PNG, or PDF — up to 10MB
                </p>
              </div>
            )}
          </div>

          {/* Type selector */}
          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium text-slate-600">
              Record type
            </label>
            <div className="flex flex-wrap gap-2">
              {RECORD_TYPES.map((t) => (
                <button
                  key={t.value}
                  type="button"
                  onClick={() => setType(t.value)}
                  className={`px-3.5 py-2 text-sm font-medium rounded-lg transition-colors ${
                    type === t.value
                      ? "bg-[#0891B2] text-white"
                      : "bg-white text-slate-500 border border-[#E5F0F6] hover:border-[#0891B2]/40"
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1.5">
              <label className="text-sm font-medium text-slate-600">
                Doctor / hospital name
              </label>
              <input
                type="text"
                value={doctorName}
                onChange={(e) => setDoctorName(e.target.value)}
                placeholder="Dr. Sharma, City Hospital"
                className="px-3.5 py-2.5 text-sm bg-white border border-[#C8E4F0] rounded-xl
                           focus:outline-none focus:border-[#0891B2] focus:ring-2 focus:ring-[#0891B2]/15"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-sm font-medium text-slate-600">
                Record date
              </label>
              <input
                type="date"
                value={recordDate}
                onChange={(e) => setRecordDate(e.target.value)}
                className="px-3.5 py-2.5 text-sm bg-white border border-[#C8E4F0] rounded-xl
                           focus:outline-none focus:border-[#0891B2] focus:ring-2 focus:ring-[#0891B2]/15"
              />
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium text-slate-600">
              Notes (optional)
            </label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={3}
              placeholder="Any additional context about this record..."
              className="px-3.5 py-2.5 text-sm bg-white border border-[#C8E4F0] rounded-xl resize-none
                         focus:outline-none focus:border-[#0891B2] focus:ring-2 focus:ring-[#0891B2]/15"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 text-sm font-semibold text-white rounded-xl hover:opacity-90 transition-opacity disabled:opacity-50"
            style={{ background: "linear-gradient(135deg, #22D3EE, #0891B2)" }}
          >
            {loading ? "Uploading..." : "Upload Record"}
          </button>
        </form>
      </div>
    </div>
  );
}
