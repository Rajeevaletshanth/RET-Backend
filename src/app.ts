import express, { type Application, type Request, type Response } from "express"
import cors from "cors"
import cookieParser from "cookie-parser"
import authRoutes from "./routes/auth.routes"
import adminRoutes from "./routes/admin.routes"
import protectedRoutes from "./routes/protected.routes"

const app: Application = express()

// Middleware
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())

// Health check
app.get("/health", (req: Request, res: Response) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() })
})

// Routes
app.use("/api/auth", authRoutes)
app.use("/api/admin", adminRoutes)
app.use("/api/protected", protectedRoutes)

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({ error: "Route not found" })
})

export default app
