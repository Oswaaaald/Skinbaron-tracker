type AdminRoleLike = {
  is_admin?: boolean
  is_super_admin?: boolean
} | null | undefined

export function canAccessAdmin(user: AdminRoleLike): boolean {
  return Boolean(user?.is_admin || user?.is_super_admin)
}
