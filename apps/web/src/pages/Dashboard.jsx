export default function Dashboard() {
  const user = JSON.parse(localStorage.getItem("medlink_user") || "{}");
  return (
    <div className="min-h-screen flex items-center justify-center bg-[#F0F9FF]">
      <div className="text-center">
        <h1 className="font-display text-3xl font-bold text-[#0F172A]">
          Welcome, {user.name}
        </h1>
        <p className="text-slate-500 mt-2">Dashboard coming next.</p>
      </div>
    </div>
  );
}
