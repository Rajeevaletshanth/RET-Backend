import { Router } from "express"
import { AuthController } from "../controllers/auth.controller"
import { authenticate } from "../middleware/auth.middleware"
import { validateRegistration, validateLogin, handleValidationErrors } from "../middleware/validation.middleware"

const router = Router()

// Public routes
router.post("/register/user", validateRegistration, handleValidationErrors, AuthController.registerUser)

router.post("/register/investor", validateRegistration, handleValidationErrors, AuthController.registerInvestor)

router.post("/register/builder", validateRegistration, handleValidationErrors, AuthController.registerBuilder)

// IMPORTANT: Comment out this route in production
router.post("/register/superadmin", validateRegistration, handleValidationErrors, AuthController.registerSuperadmin)

router.post("/login", validateLogin, handleValidationErrors, AuthController.login)

router.post("/refresh-token", AuthController.refreshToken)

router.post("/logout", AuthController.logout)

// Protected routes
router.get("/profile", authenticate, AuthController.getProfile)

export default router
