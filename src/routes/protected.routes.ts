import { Router } from "express"
import { authenticate } from "../middleware/auth.middleware"
import { requireFullAccess } from "../middleware/authorization.middleware"
import type { AuthRequest } from "../middleware/auth.middleware"

const router = Router()

// All routes require authentication
router.use(authenticate)

// Limited access route - available to all authenticated users
router.get("/limited", (req: AuthRequest, res) => {
  res.json({
    message: "This is a limited access endpoint",
    user: req.user,
  })
})

// Full access route - requires KYC verification for investors/builders
router.get("/full-access", requireFullAccess, (req: AuthRequest, res) => {
  res.json({
    message: "This is a full access endpoint",
    user: req.user,
  })
})

export default router
