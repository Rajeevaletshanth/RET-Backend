import pool from "../config/database"
import { type User, UserRole, KYCStatus } from "../types"

export class UserModel {
  static async create(email: string, passwordHash: string, role: UserRole = UserRole.USER): Promise<User> {
    const kycRequired = role === UserRole.INVESTOR || role === UserRole.BUILDER
    const hasFullAccess = role === UserRole.USER || role === UserRole.SUPERADMIN || role === UserRole.ADMIN

    const query = `
      INSERT INTO users (email, password_hash, role, kyc_required, has_full_access)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `
    const values = [email, passwordHash, role, kycRequired, hasFullAccess]
    const result = await pool.query(query, values)
    return result.rows[0]
  }

  static async findByEmail(email: string): Promise<User | null> {
    const query = "SELECT * FROM users WHERE email = $1"
    const result = await pool.query(query, [email])
    return result.rows[0] || null
  }

  static async findById(id: number): Promise<User | null> {
    const query = "SELECT * FROM users WHERE id = $1"
    const result = await pool.query(query, [id])
    return result.rows[0] || null
  }

  static async updateLastActivity(userId: number): Promise<void> {
    const query = "UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE id = $1"
    await pool.query(query, [userId])
  }

  static async updateKYCStatus(userId: number, status: KYCStatus): Promise<void> {
    const hasFullAccess = status === KYCStatus.VERIFIED
    const query = `
      UPDATE users 
      SET kyc_status = $1, has_full_access = $2, updated_at = CURRENT_TIMESTAMP
      WHERE id = $3
    `
    await pool.query(query, [status, hasFullAccess, userId])
  }

  static async checkSessionTimeout(userId: number, timeoutMs: number): Promise<boolean> {
    const query = `
      SELECT last_activity 
      FROM users 
      WHERE id = $1
    `
    const result = await pool.query(query, [userId])

    if (result.rows.length === 0) return true

    const lastActivity = new Date(result.rows[0].last_activity)
    const now = new Date()
    const timeDiff = now.getTime() - lastActivity.getTime()

    return timeDiff > timeoutMs
  }

  static async getAllUsers(): Promise<User[]> {
    const query = "SELECT * FROM users ORDER BY created_at DESC"
    const result = await pool.query(query)
    return result.rows
  }

  static async updateUserStatus(userId: number, isActive: boolean): Promise<void> {
    const query = "UPDATE users SET is_active = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
    await pool.query(query, [isActive, userId])
  }
}
