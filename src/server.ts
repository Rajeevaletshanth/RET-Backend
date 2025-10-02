import app from "./app"
import dotenv from "dotenv"
import pool from "./config/database"

dotenv.config()

const PORT = process.env.PORT || 5000

// Test database connection
pool.query("SELECT NOW()", (err, res) => {
  if (err) {
    console.error("Database connection failed:", err)
    process.exit(1)
  }
  console.log("Database connected at:", res.rows[0].now)
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`)
})
