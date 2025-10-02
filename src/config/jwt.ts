import dotenv from "dotenv"

dotenv.config()

export const jwtConfig = {
  accessSecret: process.env.JWT_ACCESS_SECRET || "your_jwt_access_secret",
  refreshSecret: process.env.JWT_REFRESH_SECRET || "your_jwt_refresh_secret",
  accessExpiry: process.env.JWT_ACCESS_EXPIRY || "15m",
  refreshExpiry: process.env.JWT_REFRESH_EXPIRY || "7d",
  sessionTimeout: Number.parseInt(process.env.SESSION_TIMEOUT || "900000"), // 15 minutes in milliseconds
}
