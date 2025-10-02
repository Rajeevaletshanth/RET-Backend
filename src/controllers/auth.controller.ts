import type { Request, Response } from "express"
import { UserModel } from "../models/User.model"
import { RefreshTokenModel } from "../models/RefreshToken.model"
import { PasswordUtil } from "../utils/password.util"
import { JWTUtil } from "../utils/jwt.util"
import { UserRole, type JWTPayload } from "../types"
import type { AuthRequest } from "../middleware/auth.middleware"

export class AuthController {
  // Regular user registration
  static async registerUser(req: Request, res: Response): Promise<void> {
    try {
      const { email, password } = req.body

      const existingUser = await UserModel.findByEmail(email)
      if (existingUser) {
        res.status(400).json({ error: "Email already registered" })
        return
      }

      const passwordHash = await PasswordUtil.hash(password)
      const user = await UserModel.create(email, passwordHash, UserRole.USER)

      res.status(201).json({
        message: "User registered successfully",
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          hasFullAccess: user.has_full_access,
        },
      })
    } catch (error) {
      console.error("Registration error:", error)
      res.status(500).json({ error: "Registration failed" })
    }
  }

  // Investor registration (requires KYC)
  static async registerInvestor(req: Request, res: Response): Promise<void> {
    try {
      const { email, password } = req.body

      const existingUser = await UserModel.findByEmail(email)
      if (existingUser) {
        res.status(400).json({ error: "Email already registered" })
        return
      }

      const passwordHash = await PasswordUtil.hash(password)
      const user = await UserModel.create(email, passwordHash, UserRole.INVESTOR)

      res.status(201).json({
        message: "Investor registered successfully. Please complete KYC verification.",
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          kycRequired: user.kyc_required,
          hasFullAccess: user.has_full_access,
        },
      })
    } catch (error) {
      console.error("Investor registration error:", error)
      res.status(500).json({ error: "Registration failed" })
    }
  }

  // Builder registration (requires KYC)
  static async registerBuilder(req: Request, res: Response): Promise<void> {
    try {
      const { email, password } = req.body

      const existingUser = await UserModel.findByEmail(email)
      if (existingUser) {
        res.status(400).json({ error: "Email already registered" })
        return
      }

      const passwordHash = await PasswordUtil.hash(password)
      const user = await UserModel.create(email, passwordHash, UserRole.BUILDER)

      res.status(201).json({
        message: "Builder registered successfully. Please complete KYC verification.",
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          kycRequired: user.kyc_required,
          hasFullAccess: user.has_full_access,
        },
      })
    } catch (error) {
      console.error("Builder registration error:", error)
      res.status(500).json({ error: "Registration failed" })
    }
  }

  // Superadmin registration (should be commented out in production)
  static async registerSuperadmin(req: Request, res: Response): Promise<void> {
    try {
      const { email, password, secretKey } = req.body

      // Add a secret key check for additional security
      if (secretKey !== process.env.SUPERADMIN_SECRET_KEY) {
        res.status(403).json({ error: "Invalid secret key" })
        return
      }

      const existingUser = await UserModel.findByEmail(email)
      if (existingUser) {
        res.status(400).json({ error: "Email already registered" })
        return
      }

      const passwordHash = await PasswordUtil.hash(password)
      const user = await UserModel.create(email, passwordHash, UserRole.SUPERADMIN)

      res.status(201).json({
        message: "Superadmin registered successfully",
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          hasFullAccess: user.has_full_access,
        },
      })
    } catch (error) {
      console.error("Superadmin registration error:", error)
      res.status(500).json({ error: "Registration failed" })
    }
  }

  // Login
  static async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password } = req.body

      const user = await UserModel.findByEmail(email)
      if (!user) {
        res.status(401).json({ error: "Invalid credentials" })
        return
      }

      if (!user.is_active) {
        res.status(403).json({ error: "Account is deactivated" })
        return
      }

      const isPasswordValid = await PasswordUtil.compare(password, user.password_hash)
      if (!isPasswordValid) {
        res.status(401).json({ error: "Invalid credentials" })
        return
      }

      // Update last activity
      await UserModel.updateLastActivity(user.id)

      const payload: JWTPayload = {
        userId: user.id,
        email: user.email,
        role: user.role,
        hasFullAccess: user.has_full_access,
      }

      const accessToken = JWTUtil.generateAccessToken(payload)
      const refreshToken = JWTUtil.generateRefreshToken(payload)

      // Store refresh token in database
      const expiresAt = JWTUtil.getRefreshTokenExpiry()
      await RefreshTokenModel.create(user.id, refreshToken, expiresAt)

      res.json({
        message: "Login successful",
        accessToken,
        refreshToken,
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          hasFullAccess: user.has_full_access,
          kycStatus: user.kyc_status,
        },
      })
    } catch (error) {
      console.error("Login error:", error)
      res.status(500).json({ error: "Login failed" })
    }
  }

  // Refresh token
  static async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken } = req.body

      if (!refreshToken) {
        res.status(400).json({ error: "Refresh token required" })
        return
      }

      // Verify refresh token
      const decoded = JWTUtil.verifyRefreshToken(refreshToken)

      // Check if token exists in database
      const storedToken = await RefreshTokenModel.findByToken(refreshToken)
      if (!storedToken) {
        res.status(401).json({ error: "Invalid refresh token" })
        return
      }

      // Check if token is expired
      if (new Date() > new Date(storedToken.expires_at)) {
        await RefreshTokenModel.deleteByToken(refreshToken)
        res.status(401).json({ error: "Refresh token expired" })
        return
      }

      // Get updated user data
      const user = await UserModel.findById(decoded.userId)
      if (!user || !user.is_active) {
        res.status(401).json({ error: "User not found or inactive" })
        return
      }

      // Update last activity and token usage
      await UserModel.updateLastActivity(user.id)
      await RefreshTokenModel.updateLastUsed(storedToken.id)

      const payload: JWTPayload = {
        userId: user.id,
        email: user.email,
        role: user.role,
        hasFullAccess: user.has_full_access,
      }

      const newAccessToken = JWTUtil.generateAccessToken(payload)

      res.json({
        message: "Token refreshed successfully",
        accessToken: newAccessToken,
      })
    } catch (error) {
      console.error("Token refresh error:", error)
      res.status(401).json({ error: "Invalid refresh token" })
    }
  }

  // Logout
  static async logout(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { refreshToken } = req.body

      if (refreshToken) {
        await RefreshTokenModel.deleteByToken(refreshToken)
      }

      // If user is authenticated, delete all their refresh tokens
      if (req.user) {
        await RefreshTokenModel.deleteByUserId(req.user.userId)
      }

      res.json({ message: "Logout successful" })
    } catch (error) {
      console.error("Logout error:", error)
      res.status(500).json({ error: "Logout failed" })
    }
  }

  // Get current user profile
  static async getProfile(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ error: "Unauthorized" })
        return
      }

      const user = await UserModel.findById(req.user.userId)
      if (!user) {
        res.status(404).json({ error: "User not found" })
        return
      }

      res.json({
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          kycStatus: user.kyc_status,
          hasFullAccess: user.has_full_access,
          kycRequired: user.kyc_required,
          createdAt: user.created_at,
        },
      })
    } catch (error) {
      console.error("Get profile error:", error)
      res.status(500).json({ error: "Failed to fetch profile" })
    }
  }
}
