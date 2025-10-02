import { Router } from "express"
import { AdminController } from "../controllers/admin.controller"
import { authenticate } from "../middleware/auth.middleware"
import { authorize } from "../middleware/authorization.middleware"
import { UserRole } from "../types"
import { validateRegistration, handleValidationErrors } from "../middleware/validation.middleware"

const router = Router()

// All routes require authentication
router.use(authenticate)

// Superadmin only - create admin
router.post(
  "/create-admin",
  authorize(UserRole.SUPERADMIN),
  validateRegistration,
  handleValidationErrors,
  AdminController.createAdmin,
)

// Admin and Superadmin - get all users
router.get("/users", authorize(UserRole.ADMIN, UserRole.SUPERADMIN), AdminController.getAllUsers)

// Admin and Superadmin - verify KYC
router.patch("/users/:userId/kyc", authorize(UserRole.ADMIN, UserRole.SUPERADMIN), AdminController.verifyKYC)

// Admin and Superadmin - toggle user status
router.patch("/users/:userId/status", authorize(UserRole.ADMIN, UserRole.SUPERADMIN), AdminController.toggleUserStatus)

export default router
