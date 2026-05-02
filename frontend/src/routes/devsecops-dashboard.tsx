import { createFileRoute } from "@tanstack/react-router"
import DevSecOpsDashboard from "../DevSecOpsDashboard"

export const Route = createFileRoute("/devsecops-dashboard")({
  component: DevSecOpsDashboard,
})
