import type { Response, NextFunction } from "express"
import type { AuthRequest } from "./auth.middleware"
import type { UserRole } from "../types"

export const authorize = (...allowedRoles: UserRole[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: "Unauthorized" })
      return
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({ error: "Forbidden: Insufficient permissions" })
      return
    }

    next()
  }
}

export const requireFullAccess = (req: AuthRequest, res: Response, next: NextFunction): void => {
  if (!req.user) {
    res.status(401).json({ error: "Unauthorized" })
    return
  }

  if (!req.user.hasFullAccess) {
    res.status(403).json({
      error: "Limited access: Please complete KYC verification",
      message: "Your account requires KYC verification for full access",
    })
    return
  }

  next()
}
