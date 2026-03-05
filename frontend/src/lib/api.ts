import type { AuthApiMethods } from './api-client/auth-methods'
import { createAuthApiMethods } from './api-client/auth-methods'
import type { DataApiMethods } from './api-client/data-methods'
import { createDataApiMethods } from './api-client/data-methods'
import type { AdminApiMethods } from './api-client/admin-methods'
import { createAdminApiMethods } from './api-client/admin-methods'
import { CoreApiClient, ApiError } from './api-client/core-client'

export type {
  Alert,
  AdminActionLog,
  AdminUser,
  AdminUserDetail,
  ApiResponse,
  AuditLog,
  CreateRuleData,
  OAuthAccount,
  PaginatedResponse,
  PasskeyAuthOptionsResponse,
  PasskeyInfo,
  PasskeyRegisterOptionsResponse,
  Rule,
  Sanction,
  SystemStats,
  UserProfile,
  Webhook,
} from './api-types'

export { ApiError }

class ApiClient extends CoreApiClient {
  constructor(baseURL?: string) {
    super(baseURL)

    Object.assign(
      this,
      createAuthApiMethods(this),
      createDataApiMethods(this),
      createAdminApiMethods(this),
    )
  }
}

export type ApiClientContract = ApiClient & AuthApiMethods & DataApiMethods & AdminApiMethods

export const apiClient = new ApiClient() as ApiClientContract
