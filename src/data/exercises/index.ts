import { cwe89Select } from './cwe-89-select'
import { cwe89Login } from './cwe-89-login'
import { cwe89Update } from './cwe-89-update'
import { cwe89Delete } from './cwe-89-delete'
import { cwe89Insert } from './cwe-89-insert'
import { cwe89Search } from './cwe-89-search'
import { cwe79Example } from './cwe-79-example'
import { cwe79Stored } from './cwe-79-stored'
import { cwe79Dom } from './cwe-79-dom'
import { cwe79Attribute } from './cwe-79-attribute'
import { cwe79Form } from './cwe-79-form'
import { cwe94Eval } from './cwe-94-eval'
import { cwe94Template } from './cwe-94-template'
import { cwe94Config } from './cwe-94-config'
import { cwe94Import } from './cwe-94-import'
import { cwe94Query } from './cwe-94-query'
import { cwe863Cookie } from './cwe-863-cookie'
import { cwe863Admin } from './cwe-863-admin'
import { cwe863Api } from './cwe-863-api'
import { cwe863Role } from './cwe-863-role'
import { cwe863Ownership } from './cwe-863-ownership'
import { cwe276File } from './cwe-276-file'
import { cwe276Directory } from './cwe-276-directory'
import { cwe276Config } from './cwe-276-config'
import { cwe276Temp } from './cwe-276-temp'
import { cwe276Key } from './cwe-276-key'

// CWE-798 Hard-coded Credentials exercises
import { cwe798ApiKey } from './cwe-798-api-key'
import { cwe798Database } from './cwe-798-database'
import { cwe798SshKey } from './cwe-798-ssh-key'
import { cwe798JwtSecret } from './cwe-798-jwt-secret'
import { cwe798AdminPassword } from './cwe-798-admin-password'

// CWE-918 Server-Side Request Forgery exercises
import { cwe918Webhook } from './cwe-918-webhook'
import { cwe918Proxy } from './cwe-918-proxy'
import { cwe918ImageFetch } from './cwe-918-image-fetch'
import { cwe918UrlPreview } from './cwe-918-url-preview'
import { cwe918HealthCheck } from './cwe-918-health-check'

// CWE-306 Missing Authentication exercises
import { cwe306AdminApi } from './cwe-306-admin-api'
import { cwe306FileUpload } from './cwe-306-file-upload'
import { cwe306PaymentApi } from './cwe-306-payment-api'
import { cwe306ConfigApi } from './cwe-306-config-api'
import { cwe306DatabaseAccess } from './cwe-306-database-access'

// CWE-362 Race Condition exercises
import { cwe362BalanceTransfer } from './cwe-362-balance-transfer'
import { cwe362InventoryUpdate } from './cwe-362-inventory-update'
import { cwe362CounterIncrement } from './cwe-362-counter-increment'
import { cwe362SessionCheck } from './cwe-362-session-check'
import { cwe362FileCreation } from './cwe-362-file-creation'

// CWE-269 Privilege Management exercises
import { cwe269PrivilegeEscalation } from './cwe-269-privilege-escalation'
import { cwe269PasswordReset } from './cwe-269-password-reset'
import { cwe269SystemCommand } from './cwe-269-system-command'
import { cwe269DataAccess } from './cwe-269-data-access'
import { cwe269PrivilegeDrop } from './cwe-269-privilege-drop'

// CWE-22 Path Traversal exercises
import { cwe22FileDownload } from './cwe-22-file-download'
import { cwe22ProfileAccess } from './cwe-22-profile-access'
import { cwe22TemplateInclude } from './cwe-22-template-include'
import { cwe22LogViewer } from './cwe-22-log-viewer'
import { cwe22ConfigReader } from './cwe-22-config-reader'

// CWE-352 Cross-Site Request Forgery exercises
import { cwe352ProfileUpdate } from './cwe-352-profile-update'
import { cwe352EmailChange } from './cwe-352-email-change'
import { cwe352AdminDelete } from './cwe-352-admin-delete'
import { cwe352PasswordChange } from './cwe-352-password-change'
import { cwe352FundTransfer } from './cwe-352-fund-transfer'

// CWE-434 Unrestricted Upload exercises
import { cwe434AvatarUpload } from './cwe-434-avatar-upload'
import { cwe434DocumentUpload } from './cwe-434-document-upload'
import { cwe434ResumeUpload } from './cwe-434-resume-upload'
import { cwe434ImageGallery } from './cwe-434-image-gallery'
import { cwe434BackupRestore } from './cwe-434-backup-restore'

// CWE-862 Missing Authorization exercises
import { cwe862UserProfile } from './cwe-862-user-profile'
import { cwe862PrivateMessages } from './cwe-862-private-messages'
import { cwe862AdminPanel } from './cwe-862-admin-panel'
import { cwe862UserOrders } from './cwe-862-user-orders'
import { cwe862FileSharing } from './cwe-862-file-sharing'

// CWE-476 NULL Pointer Dereference exercises
import { cwe476HostLookup } from './cwe-476-host-lookup'
import { cwe476SystemProperty } from './cwe-476-system-property'
import { cwe476IntentReceiver } from './cwe-476-intent-receiver'
import { cwe476HttpResponse } from './cwe-476-http-response'
import { cwe476ConfigParser } from './cwe-476-config-parser'

import type { Exercise } from '@/data/exercises'

/**
 * All CWE exercises imported from individual files
 *
 * To add a new exercise:
 * 1. Create a new file following the template in /src/templates/cwe-exercise-template.ts
 * 2. Import it above
 * 3. Add it to the exercisesList array below
 */

export const exercisesList: Exercise[] = [
  // CWE-89 SQL Injection exercises
  cwe89Select,
  cwe89Login,
  cwe89Update,
  cwe89Delete,
  cwe89Insert,
  cwe89Search,

  // CWE-79 Cross-Site Scripting exercises
  cwe79Example,
  cwe79Stored,
  cwe79Dom,
  cwe79Attribute,
  cwe79Form,

  // CWE-94 Code Injection exercises
  cwe94Eval,
  cwe94Template,
  cwe94Config,
  cwe94Import,
  cwe94Query,

  // CWE-863 Incorrect Authorization exercises
  cwe863Cookie,
  cwe863Admin,
  cwe863Api,
  cwe863Role,
  cwe863Ownership,

  // CWE-276 Incorrect Default Permissions exercises
  cwe276File,
  cwe276Directory,
  cwe276Config,
  cwe276Temp,
  cwe276Key,

  // CWE-798 Hard-coded Credentials exercises
  cwe798ApiKey,
  cwe798Database,
  cwe798SshKey,
  cwe798JwtSecret,
  cwe798AdminPassword,

  // CWE-918 Server-Side Request Forgery exercises
  cwe918Webhook,
  cwe918Proxy,
  cwe918ImageFetch,
  cwe918UrlPreview,
  cwe918HealthCheck,

  // CWE-306 Missing Authentication exercises
  cwe306AdminApi,
  cwe306FileUpload,
  cwe306PaymentApi,
  cwe306ConfigApi,
  cwe306DatabaseAccess,

  // CWE-362 Race Condition exercises
  cwe362BalanceTransfer,
  cwe362InventoryUpdate,
  cwe362CounterIncrement,
  cwe362SessionCheck,
  cwe362FileCreation,

  // CWE-269 Privilege Management exercises
  cwe269PrivilegeEscalation,
  cwe269PasswordReset,
  cwe269SystemCommand,
  cwe269DataAccess,
  cwe269PrivilegeDrop,
]

export {
  cwe89Select, cwe89Login, cwe89Update, cwe89Delete, cwe89Insert, cwe89Search,
  cwe79Example, cwe79Stored, cwe79Dom, cwe79Attribute, cwe79Form,
  cwe94Eval, cwe94Template, cwe94Config, cwe94Import, cwe94Query,
  cwe863Cookie, cwe863Admin, cwe863Api, cwe863Role, cwe863Ownership,
  cwe276File, cwe276Directory, cwe276Config, cwe276Temp, cwe276Key,
  cwe798ApiKey, cwe798Database, cwe798SshKey, cwe798JwtSecret, cwe798AdminPassword,
  cwe918Webhook, cwe918Proxy, cwe918ImageFetch, cwe918UrlPreview, cwe918HealthCheck,
  cwe306AdminApi, cwe306FileUpload, cwe306PaymentApi, cwe306ConfigApi, cwe306DatabaseAccess,
  cwe362BalanceTransfer, cwe362InventoryUpdate, cwe362CounterIncrement, cwe362SessionCheck, cwe362FileCreation,
  cwe269PrivilegeEscalation, cwe269PasswordReset, cwe269SystemCommand, cwe269DataAccess, cwe269PrivilegeDrop
}