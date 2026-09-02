import { createBrowserRouter } from "react-router"
import Home from "./pages/Home"
import Auth from "./pages/Auth"
import Dashboard from "./pages/Dashboard"

export const router = createBrowserRouter([
  { path: "/", Component: Home },
  { path: "/auth", Component: Auth },
  { path: "*", Component: Home },
  { path: "/dashboard", Component: Dashboard },
])