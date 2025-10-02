import jwt from "jsonwebtoken"
import { jwtConfig } from "../config/jwt"
import type { JWTPayload } from "../types"

export class JWTUtil {
  static generateAccessToken(payload: JWTPayload): string {
    return (jwt as any).sign(payload, jwtConfig.accessSecret as string, {
      expiresIn: jwtConfig.accessExpiry,
    })
  }

  static generateRefreshToken(payload: JWTPayload): string {
    return (jwt as any).sign(payload, jwtConfig.refreshSecret as string, {
      expiresIn: jwtConfig.refreshExpiry,
    })
  }

  static verifyAccessToken(token: string): JWTPayload {
    return jwt.verify(token, jwtConfig.accessSecret as string) as JWTPayload
  }

  static verifyRefreshToken(token: string): JWTPayload {
    return jwt.verify(token, jwtConfig.refreshSecret as string) as JWTPayload
  }

  static getRefreshTokenExpiry(): Date {
    const expiryTime = jwtConfig.refreshExpiry
    const days = Number.parseInt(expiryTime.replace("d", ""))
    const expiryDate = new Date()
    expiryDate.setDate(expiryDate.getDate() + days)
    return expiryDate
  }
}