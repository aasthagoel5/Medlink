import { createBrowserRouter } from "react-router"
import Home from "./pages/Home"
import Auth from "./pages/Auth"
import Dashboard from "./pages/Dashboard"
import RecordUpload from "./pages/RecordUpload"
import RecordDetail from "./pages/RecordDetail"

export const router = createBrowserRouter([
  { path: "/", Component: Home },
  { path: "/auth", Component: Auth },
  { path: "*", Component: Home },
  { path: "/dashboard", Component: Dashboard },
  { path: "/records/upload", Component: RecordUpload },
  { path: "/records/:id", Component: RecordDetail },
])
