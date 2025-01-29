package cloudyad

const GuidUsers = "A9D1CA15768811D1ADED00C04FD8D5CD"

const (
	AC_ACCOUNT_NEVER_EXPIRES          = 0x00000000 // 0
	AC_SCRIPT                         = 0x0001     // 1	The logon script will be run.
	AC_ACCOUNTDISABLE                 = 0x0002     // 2	The user account is disabled.
	AC_HOMEDIR_REQUIRED               = 0x0008     // 8	The home folder is required.
	AC_LOCKOUT                        = 0x0010     // 16	The account locked
	AC_PASSWD_NOTREQD                 = 0x0020     // 32	No password is required.
	AC_PASSWD_CANT_CHANGE             = 0x0040     // 64	The user can’t change the password.
	AC_ENCRYPTED_TEXT_PWD_ALLOWED     = 0x0080     // 128	The user can send an encrypted password.
	AC_TEMP_DUPLICATE_ACCOUNT         = 0x0100     // 256	It’s an account for users whose primary account is in another domain.
	AC_NORMAL_ACCOUNT                 = 0x0200     // 512	It’s a default account type that represents a typical user.
	AC_INTERDOMAIN_TRUST_ACCOUNT      = 0x0800     // 2048	It’s a permit to trust an account for a system domain that trusts other domains.
	AC_WORKSTATION_TRUST_ACCOUNT      = 0x1000     // 4096	It’s a computer account for a computer that is running Microsoft Windows NT 4.0 Workstation, NT 4.0 Server, 2000 PRO or 2000 server and is a member of this domain.
	AC_SERVER_TRUST_ACCOUNT           = 0x2000     // 8192	It’s a computer account for a domain controller that is a member of this domain.
	AC_DONT_EXPIRE_PASSWORD           = 0x10000    // 65536	Represents the password, which should never expire on the account.
	AC_MNS_LOGON_ACCOUNT              = 0x20000    // 131072	It’s an MNS logon account.
	AC_SMARTCARD_REQUIRED             = 0x40000    // 262144	When this flag is set, it forces the user to log on by using a smart card.
	AC_TRUSTED_FOR_DELEGATION         = 0x80000    // 524288	When this flag is set, the service account (the user or computer account) under which a service runs is trusted for Kerberos delegation.
	AC_NOT_DELEGATED                  = 0x100000   // 1048576	When this flag is set, the security context of the user isn’t delegated to a service even if the service account is set as trusted for Kerberos delegation.
	AC_USE_DES_KEY_ONLY               = 0x200000   // 2097152	(Windows 2000/Windows Server 2003) Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys
	AC_DONT_REQ_PREAUTH               = 0x400000   // 4194304	(Windows 2000/Windows Server 2003) This account doesn’t require Kerberos pre-authentication for logging on.
	AC_PASSWORD_EXPIRED               = 0x800000   // 8388608	(Windows 2000/Windows Server 2003) The user’s password has expired.
	AC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000  // 16777216	(Windows 2000/Windows Server 2003) The account is enabled for delegation. It’s a security-sensitive setting
	AC_PARTIAL_SECRETS_ACCOUNT        = 0x04000000 // 67108864	(Windows Server 2008/Windows Server 2008 R2) The account is a read-only domain controller (RODC). It’s a security-sensitive setting.
	AC_INSTANCE_TYPE_WRITEABLE        = 0x00000004 // The object is writable on this directory.
	ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP = 0x00000004 // Specifies a group that can contain accounts from any domain, other domain local groups from the same domain, global groups from any domain, and universal groups.
	ADS_GROUP_TYPE_SECURITY_ENABLED   = 0x80000000 // Specifies a group that is security enabled. This group can be used to apply an access-control list on an ADSI object or a file system.
)

// 0 means use default in client
const TICKER_DURATION = 0
const MAX_ATTEMPTS = 0

const DISPLAY_NAME_TYPE = "displayName"
const NAME_TYPE = "name"
const FIRST_NAME_TYPE = "givenName"
const LAST_NAME_TYPE = "sn"
const EMAIL_TYPE = "mail"
const LAST_LOGIN_TYPE = "lastLogon"
const USER_ACCOUNT_CONTROL_TYPE = "userAccountControl"
const USER_PRINCIPAL_NAME_TYPE = "userPrincipalName"
const USERNAME_TYPE = "cn"
const ACCT_EXPIRES_TYPE = "accountExpires"
const OBJ_CLASS_TYPE = "objectClass"
const INSTANCE_TYPE = "instanceType"
const SAM_ACCT_NAME_TYPE = "sAMAccountName"
const PASSWORD_LAST_SET = "pwdLastSet"

const GROUP_NAME_TYPE = "name"
const GROUP_TYPE = "groupType"
const GROUP_COMMON_NAME = "cn"
const GROUP_SOURCE = "Active Directory"

var USER_OBJ_CLASS_VALS = []string{"top", "organizationalPerson", "user", "person"}
var GROUP_OBJ_CLASS_VALS = []string{"top", "group"}

var USER_STANDARD_ATTRS = []string{FIRST_NAME_TYPE, LAST_NAME_TYPE, EMAIL_TYPE, DISPLAY_NAME_TYPE, LAST_LOGIN_TYPE, USERNAME_TYPE, USER_ACCOUNT_CONTROL_TYPE, USER_PRINCIPAL_NAME_TYPE}
var USER_OBJECT_ATTRS = []string{FIRST_NAME_TYPE, LAST_NAME_TYPE, EMAIL_TYPE, DISPLAY_NAME_TYPE, USERNAME_TYPE, USER_ACCOUNT_CONTROL_TYPE}
var GROUP_STANDARD_ATTRS = []string{GROUP_NAME_TYPE, GROUP_TYPE, GROUP_COMMON_NAME}
