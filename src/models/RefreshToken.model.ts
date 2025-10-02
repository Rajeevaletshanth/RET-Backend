import pool from "../config/database"
import type { RefreshToken } from "../types"

export class RefreshTokenModel {
  static async create(userId: number, token: string, expiresAt: Date): Promise<RefreshToken> {
    const query = `
      INSERT INTO refresh_tokens (user_id, token, expires_at)
      VALUES ($1, $2, $3)
      RETURNING *
    `
    const values = [userId, token, expiresAt]
    const result = await pool.query(query, values)
    return result.rows[0]
  }

  static async findByToken(token: string): Promise<RefreshToken | null> {
    const query = "SELECT * FROM refresh_tokens WHERE token = $1"
    const result = await pool.query(query, [token])
    return result.rows[0] || null
  }

  static async updateLastUsed(tokenId: number): Promise<void> {
    const query = "UPDATE refresh_tokens SET last_used = CURRENT_TIMESTAMP WHERE id = $1"
    await pool.query(query, [tokenId])
  }

  static async deleteByToken(token: string): Promise<void> {
    const query = "DELETE FROM refresh_tokens WHERE token = $1"
    await pool.query(query, [token])
  }

  static async deleteByUserId(userId: number): Promise<void> {
    const query = "DELETE FROM refresh_tokens WHERE user_id = $1"
    await pool.query(query, [userId])
  }

  static async deleteExpiredTokens(): Promise<void> {
    const query = "DELETE FROM refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP"
    await pool.query(query)
  }
}
