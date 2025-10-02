import jwt from "jsonwebtoken"
import { jwtConfig } from "../config/jwt"
import type { JWTPayload } from "../types"

export class JWTUtil {
  static generateAccessToken(payload: JWTPayload): string {
    return jwt.sign(payload, jwtConfig.accessSecret, {
      expiresIn: jwtConfig.accessExpiry,
    })
  }

  static generateRefreshToken(payload: JWTPayload): string {
    return jwt.sign(payload, jwtConfig.refreshSecret, {
      expiresIn: jwtConfig.refreshExpiry,
    })
  }

  static verifyAccessToken(token: string): JWTPayload {
    return jwt.verify(token, jwtConfig.accessSecret) as JWTPayload
  }

  static verifyRefreshToken(token: string): JWTPayload {
    return jwt.verify(token, jwtConfig.refreshSecret) as JWTPayload
  }

  static getRefreshTokenExpiry(): Date {
    const expiryTime = jwtConfig.refreshExpiry
    const days = Number.parseInt(expiryTime.replace("d", ""))
    const expiryDate = new Date()
    expiryDate.setDate(expiryDate.getDate() + days)
    return expiryDate
  }
}
