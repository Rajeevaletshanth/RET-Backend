import type { Request, Response, NextFunction } from "express"
import { JWTUtil } from "../utils/jwt.util"
import { UserModel } from "../models/User.model"
import { jwtConfig } from "../config/jwt"
import type { JWTPayload } from "../types"

export interface AuthRequest extends Request {
  user?: JWTPayload
}

export const authenticate = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authHeader = req.headers.authorization

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({ error: "No token provided" })
      return
    }

    const token = authHeader.substring(7)

    try {
      const decoded = JWTUtil.verifyAccessToken(token)

      // Check session timeout
      const isTimedOut = await UserModel.checkSessionTimeout(decoded.userId, jwtConfig.sessionTimeout)

      if (isTimedOut) {
        res.status(401).json({ error: "Session expired due to inactivity" })
        return
      }

      // Update last activity
      await UserModel.updateLastActivity(decoded.userId)

      req.user = decoded
      next()
    } catch (error) {
      res.status(401).json({ error: "Invalid or expired token" })
      return
    }
  } catch (error) {
    res.status(500).json({ error: "Authentication error" })
    return
  }
}
