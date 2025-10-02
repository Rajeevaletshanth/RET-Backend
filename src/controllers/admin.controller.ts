import type { Response } from "express"
import { UserModel } from "../models/User.model"
import { PasswordUtil } from "../utils/password.util"
import { UserRole, KYCStatus } from "../types"
import type { AuthRequest } from "../middleware/auth.middleware"

export class AdminController {
  // Superadmin creates admin
  static async createAdmin(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { email, password } = req.body

      const existingUser = await UserModel.findByEmail(email)
      if (existingUser) {
        res.status(400).json({ error: "Email already registered" })
        return
      }

      const passwordHash = await PasswordUtil.hash(password)
      const admin = await UserModel.create(email, passwordHash, UserRole.ADMIN)

      res.status(201).json({
        message: "Admin created successfully",
        admin: {
          id: admin.id,
          email: admin.email,
          role: admin.role,
          hasFullAccess: admin.has_full_access,
        },
      })
    } catch (error) {
      console.error("Create admin error:", error)
      res.status(500).json({ error: "Failed to create admin" })
    }
  }

  // Get all users (admin and superadmin only)
  static async getAllUsers(req: AuthRequest, res: Response): Promise<void> {
    try {
      const users = await UserModel.getAllUsers()

      const sanitizedUsers = users.map((user) => ({
        id: user.id,
        email: user.email,
        role: user.role,
        isActive: user.is_active,
        kycStatus: user.kyc_status,
        hasFullAccess: user.has_full_access,
        createdAt: user.created_at,
        lastActivity: user.last_activity,
      }))

      res.json({ users: sanitizedUsers })
    } catch (error) {
      console.error("Get all users error:", error)
      res.status(500).json({ error: "Failed to fetch users" })
    }
  }

  // Verify KYC (admin and superadmin only)
  static async verifyKYC(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { userId } = req.params
      const { status } = req.body

      if (!Object.values(KYCStatus).includes(status)) {
        res.status(400).json({ error: "Invalid KYC status" })
        return
      }

      const user = await UserModel.findById(Number.parseInt(userId))
      if (!user) {
        res.status(404).json({ error: "User not found" })
        return
      }

      if (!user.kyc_required) {
        res.status(400).json({ error: "User does not require KYC verification" })
        return
      }

      await UserModel.updateKYCStatus(Number.parseInt(userId), status)

      res.json({
        message: `KYC status updated to ${status}`,
        userId: Number.parseInt(userId),
        kycStatus: status,
        hasFullAccess: status === KYCStatus.VERIFIED,
      })
    } catch (error) {
      console.error("Verify KYC error:", error)
      res.status(500).json({ error: "Failed to verify KYC" })
    }
  }

  // Deactivate/Activate user
  static async toggleUserStatus(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { userId } = req.params
      const { isActive } = req.body

      const user = await UserModel.findById(Number.parseInt(userId))
      if (!user) {
        res.status(404).json({ error: "User not found" })
        return
      }

      // Prevent deactivating superadmin
      if (user.role === UserRole.SUPERADMIN) {
        res.status(403).json({ error: "Cannot deactivate superadmin" })
        return
      }

      await UserModel.updateUserStatus(Number.parseInt(userId), isActive)

      res.json({
        message: `User ${isActive ? "activated" : "deactivated"} successfully`,
        userId: Number.parseInt(userId),
        isActive,
      })
    } catch (error) {
      console.error("Toggle user status error:", error)
      res.status(500).json({ error: "Failed to update user status" })
    }
  }
}
