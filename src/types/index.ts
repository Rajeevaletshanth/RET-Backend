export enum UserRole {
  SUPERADMIN = "superadmin",
  ADMIN = "admin",
  INVESTOR = "investor",
  BUILDER = "builder",
  USER = "user",
}

export enum KYCStatus {
  PENDING = "pending",
  SUBMITTED = "submitted",
  VERIFIED = "verified",
  REJECTED = "rejected",
}

export interface User {
  id: number
  email: string
  password_hash: string
  role: UserRole
  is_active: boolean
  kyc_status: KYCStatus
  kyc_required: boolean
  has_full_access: boolean
  created_at: Date
  updated_at: Date
  last_activity: Date
}

export interface RefreshToken {
  id: number
  user_id: number
  token: string
  expires_at: Date
  created_at: Date
  last_used: Date
}

export interface JWTPayload {
  userId: number
  email: string
  role: UserRole
  hasFullAccess: boolean
}

export interface AuthRequest extends Request {
  user?: JWTPayload
}
