import { useEffect, useState } from "react"
import { useNavigate } from "react-router"
import { MedlinkLogo } from "../components/Logo"
import { getRecords } from "../lib/recordsApi"

const TYPE_LABELS = {
  prescription: "Prescription",
  lab_report: "Lab Report",
  scan: "Scan",
  vaccination: "Vaccination",
  other: "Other",
}

const TYPE_STRIPES = {
  prescription: "#0891B2",
  lab_report: "#0D9488",
  scan: "#22D3EE",
  vaccination: "#94A3B8",
  other: "#CBD5E1",
}

function RecordCard({ record, onClick }) {
  return (
    <button
      onClick={onClick}
      className="text-left bg-white rounded-2xl border border-[#E5F0F6] p-4 pl-5 hover:border-[#0891B2]/40 transition-colors relative"
      style={{ borderLeft: `3px solid ${TYPE_STRIPES[record.type] || "#CBD5E1"}` }}
    >
      <div className="flex items-start justify-between mb-1">
        <span className="text-xs font-semibold text-[#0891B2] uppercase tracking-wide">
          {TYPE_LABELS[record.type] || record.type}
        </span>
      </div>
      <p className="text-sm font-medium text-[#0F172A] mb-1">
        {record.doctorName || "Unnamed record"}
      </p>
      <p className="text-xs text-slate-400">
        {record.recordDate
          ? new Date(record.recordDate).toLocaleDateString()
          : new Date(record.createdAt).toLocaleDateString()}
      </p>
    </button>
  )
}

function EmptyState({ onUpload }) {
  return (
    <div className="text-center py-24">
      <p className="text-slate-400 mb-4">You haven't uploaded any records yet.</p>
      <button
        onClick={onUpload}
        className="px-5 py-2.5 text-sm font-semibold text-white rounded-xl hover:opacity-90 transition-opacity"
        style={{ background: "linear-gradient(135deg, #22D3EE, #0891B2)" }}
      >
        Upload your first record
      </button>
    </div>
  )
}

export default function Dashboard() {
  const navigate = useNavigate()
  const user = JSON.parse(localStorage.getItem('medlink_user') || '{}')

  const [records, setRecords] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [search, setSearch] = useState("")
  const [activeFilter, setActiveFilter] = useState("all")

  useEffect(() => {
    const token = localStorage.getItem('medlink_token')
    if (!token) {
      navigate('/auth')
      return
    }

    getRecords()
      .then((data) => setRecords(data))
      .catch((err) => {
        if (err.response?.status === 401) {
          localStorage.removeItem('medlink_token')
          navigate('/auth')
        } else {
          setError('Failed to load records')
        }
      })
      .finally(() => setLoading(false))
  }, [navigate])

  const filteredRecords = records.filter((r) => {
    const matchesFilter = activeFilter === "all" || r.type === activeFilter
    const matchesSearch =
      !search ||
      r.doctorName?.toLowerCase().includes(search.toLowerCase()) ||
      r.notes?.toLowerCase().includes(search.toLowerCase())
    return matchesFilter && matchesSearch
  })

  const handleLogout = () => {
    localStorage.removeItem('medlink_token')
    localStorage.removeItem('medlink_user')
    navigate('/')
  }

  return (
    <div className="min-h-screen bg-[#F0F9FF]">
      <nav className="sticky top-0 z-50 bg-[#F0F9FF]/95 backdrop-blur-md border-b border-sky-200">
        <div className="max-w-6xl mx-auto px-8 h-16 flex items-center justify-between">
          <MedlinkLogo size={34} showName />
          <div className="flex items-center gap-4">
            <span className="text-sm text-slate-500">{user.name}</span>
            <button
              onClick={handleLogout}
              className="text-sm text-slate-500 hover:text-[#0891B2] transition-colors"
            >
              Log out
            </button>
          </div>
        </div>
      </nav>

      <div className="max-w-6xl mx-auto px-8 py-10">
        <div className="flex items-center justify-between mb-8">
          <h1 className="font-display text-3xl font-bold text-[#0F172A]">Your Records</h1>
          <button
            onClick={() => navigate('/records/upload')}
            className="px-5 py-2.5 text-sm font-semibold text-white rounded-xl hover:opacity-90 transition-opacity shadow-[0_4px_16px_rgba(8,145,178,0.25)]"
            style={{ background: "linear-gradient(135deg, #22D3EE, #0891B2)" }}
          >
            + Upload Record
          </button>
        </div>

        <div className="flex flex-col sm:flex-row gap-3 mb-6">
          <input
            type="text"
            placeholder="Search by doctor or notes..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="flex-1 px-4 py-2.5 text-sm bg-white border border-[#C8E4F0] rounded-xl
                       focus:outline-none focus:border-[#0891B2] focus:ring-2 focus:ring-[#0891B2]/15"
          />
          <div className="flex gap-2 overflow-x-auto">
            {["all", "prescription", "lab_report", "scan", "vaccination", "other"].map((type) => (
              <button
                key={type}
                onClick={() => setActiveFilter(type)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-full whitespace-nowrap transition-colors ${
                  activeFilter === type
                    ? "bg-[#0891B2] text-white"
                    : "bg-white text-slate-500 border border-[#E5F0F6] hover:border-[#0891B2]/40"
                }`}
              >
                {type === "all" ? "All" : TYPE_LABELS[type]}
              </button>
            ))}
          </div>
        </div>

        {loading && <p className="text-slate-400 text-center py-24">Loading your records...</p>}

        {error && <p className="text-red-500 text-center py-24">{error}</p>}

        {!loading && !error && filteredRecords.length === 0 && records.length === 0 && (
          <EmptyState onUpload={() => navigate('/records/upload')} />
        )}

        {!loading && !error && filteredRecords.length === 0 && records.length > 0 && (
          <p className="text-slate-400 text-center py-24">No records match your search.</p>
        )}

        {!loading && !error && filteredRecords.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredRecords.map((record) => (
              <RecordCard
                key={record._id}
                record={record}
                onClick={() => navigate(`/records/${record._id}`)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}