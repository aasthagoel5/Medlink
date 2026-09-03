import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { MedlinkLogo } from "../components/Logo";
import { getRecordById, deleteRecord } from "../lib/recordsApi";
import ShareModal from "../components/ShareModal";

const TYPE_LABELS = {
  prescription: "Prescription",
  lab_report: "Lab Report",
  scan: "Scan",
  vaccination: "Vaccination",
  other: "Other",
};

export default function RecordDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [record, setRecord] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showShareModal, setShowShareModal] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  useEffect(() => {
    getRecordById(id)
      .then(setRecord)
      .catch(() => setError("Record not found"))
      .finally(() => setLoading(false));
  }, [id]);

  const handleDelete = async () => {
    await deleteRecord(id);
    navigate("/dashboard");
  };

  const isImage = record?.fileUrl?.match(/\.(jpg|jpeg|png|gif)$/i);

  if (loading)
    return <p className="text-center py-24 text-slate-400">Loading...</p>;
  if (error) return <p className="text-center py-24 text-red-500">{error}</p>;

  return (
    <div className="min-h-screen bg-[#F0F9FF]">
      <nav className="sticky top-0 z-50 bg-[#F0F9FF]/95 backdrop-blur-md border-b border-sky-200">
        <div className="max-w-4xl mx-auto px-8 h-16 flex items-center">
          <MedlinkLogo size={34} showName />
        </div>
      </nav>

      <div className="max-w-4xl mx-auto px-8 py-10">
        <button
          onClick={() => navigate("/dashboard")}
          className="text-sm text-slate-500 hover:text-[#0891B2] transition-colors mb-6"
        >
          ← Back to records
        </button>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* File preview */}
          <div className="bg-white rounded-2xl border border-[#E5F0F6] overflow-hidden">
            {isImage ? (
              <img
                src={record.fileUrl}
                alt="Record"
                className="w-full h-auto"
              />
            ) : (
              <div className="p-10 text-center">
                <p className="text-sm text-slate-500 mb-3">PDF document</p>
                <a
                  href={record.fileUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="text-sm text-[#0891B2] hover:underline"
                >
                  Open file →
                </a>
              </div>
            )}
          </div>

          {/* Metadata */}
          <div>
            <span className="text-xs font-semibold text-[#0891B2] uppercase tracking-wide">
              {TYPE_LABELS[record.type] || record.type}
            </span>
            <h1 className="font-display text-2xl font-bold text-[#0F172A] mt-1 mb-4">
              {record.doctorName || "Unnamed record"}
            </h1>

            <div className="space-y-2 text-sm text-slate-600 mb-6">
              <p>
                <span className="text-slate-400">Date:</span>{" "}
                {record.recordDate
                  ? new Date(record.recordDate).toLocaleDateString()
                  : new Date(record.createdAt).toLocaleDateString()}
              </p>
              {record.notes && (
                <p>
                  <span className="text-slate-400">Notes:</span> {record.notes}
                </p>
              )}
            </div>

            {/* Extracted text from OCR */}
            {record.extractedText && (
              <div className="p-4 rounded-xl bg-[#F0FDFF] border border-[#C8E4F0] mb-6">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs font-semibold text-[#0891B2]">
                    Extracted Text
                  </p>
                  {record.ocrConfidence !== null &&
                    record.ocrConfidence !== undefined && (
                      <span
                        className={`text-xs font-medium ${
                          record.ocrConfidence >= 80
                            ? "text-emerald-600"
                            : record.ocrConfidence >= 50
                              ? "text-amber-600"
                              : "text-red-500"
                        }`}
                      >
                        {record.ocrConfidence >= 80
                          ? "High confidence"
                          : record.ocrConfidence >= 50
                            ? "Medium confidence"
                            : "Low confidence — please verify"}
                      </span>
                    )}
                </div>
                <p className="text-xs text-slate-600 leading-relaxed whitespace-pre-line max-h-48 overflow-y-auto">
                  {record.extractedText}
                </p>
              </div>
            )}

            {!record.extractedText && (
              <div className="p-4 rounded-xl bg-[#F0FDFF] border border-[#C8E4F0] mb-6">
                <p className="text-xs font-semibold text-[#0891B2] mb-1">
                  Extracted Text
                </p>
                <p className="text-xs text-slate-400">
                  No text could be extracted from this file.
                </p>
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={() => setShowShareModal(true)}
                className="flex-1 py-2.5 text-sm font-semibold text-white rounded-xl hover:opacity-90 transition-opacity"
                style={{
                  background: "linear-gradient(135deg, #22D3EE, #0891B2)",
                }}
              >
                Share
              </button>
              <button
                onClick={() => setShowDeleteConfirm(true)}
                className="px-4 py-2.5 text-sm font-medium text-red-500 border border-red-200 rounded-xl hover:bg-red-50"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      </div>

      {showShareModal && (
        <ShareModal
          recordId={record._id}
          onClose={() => setShowShareModal(false)}
        />
      )}

      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 px-4">
          <div className="bg-white rounded-2xl p-6 w-full max-w-sm">
            <h3 className="font-display text-lg font-semibold text-[#0F172A] mb-2">
              Delete this record?
            </h3>
            <p className="text-sm text-slate-500 mb-6">This can't be undone.</p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowDeleteConfirm(false)}
                className="flex-1 py-2.5 text-sm font-medium text-slate-500 border border-[#E5F0F6] rounded-xl hover:bg-slate-50"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                className="flex-1 py-2.5 text-sm font-semibold text-white bg-red-500 rounded-xl hover:bg-red-600"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
