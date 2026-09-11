import { createBrowserRouter } from "react-router"
import Home from "./pages/Home"
import Auth from "./pages/Auth"
import Dashboard from "./pages/Dashboard"
import RecordUpload from "./pages/RecordUpload"
import RecordDetail from "./pages/RecordDetail"
import SharedRecord from "./pages/SharedRecord"
import ProfileSetup from "./pages/ProfileSetup"

export const router = createBrowserRouter([
  { path: "/", Component: Home },
  { path: "/auth", Component: Auth },
  { path: "/dashboard", Component: Dashboard },
  { path: "/records/upload", Component: RecordUpload },
  { path: "/records/:id", Component: RecordDetail },
  { path: "/shared/:token", Component: SharedRecord },
  { path: "/profile-setup", Component: ProfileSetup },
  { path: "*", Component: Home },
])
