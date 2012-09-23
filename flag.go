package pkcs11

// Generated with:
// grep CKF *t.h|grep '#define' | sed 's/^#define //' | awk ' { print $1 "=" $2 } '

const (
	CKF_TOKEN_PRESENT                  = 0x00000001
	CKF_REMOVABLE_DEVICE               = 0x00000002
	CKF_HW_SLOT                        = 0x00000004
	CKF_RNG                            = 0x00000001
	CKF_WRITE_PROTECTED                = 0x00000002
	CKF_LOGIN_REQUIRED                 = 0x00000004
	CKF_USER_PIN_INITIALIZED           = 0x00000008
	CKF_RESTORE_KEY_NOT_NEEDED         = 0x00000020
	CKF_CLOCK_ON_TOKEN                 = 0x00000040
	CKF_PROTECTED_AUTHENTICATION_PATH  = 0x00000100
	CKF_DUAL_CRYPTO_OPERATIONS         = 0x00000200
	CKF_TOKEN_INITIALIZED              = 0x00000400
	CKF_SECONDARY_AUTHENTICATION       = 0x00000800
	CKF_USER_PIN_COUNT_LOW             = 0x00010000
	CKF_USER_PIN_FINAL_TRY             = 0x00020000
	CKF_USER_PIN_LOCKED                = 0x00040000
	CKF_USER_PIN_TO_BE_CHANGED         = 0x00080000
	CKF_SO_PIN_COUNT_LOW               = 0x00100000
	CKF_SO_PIN_FINAL_TRY               = 0x00200000
	CKF_SO_PIN_LOCKED                  = 0x00400000
	CKF_SO_PIN_TO_BE_CHANGED           = 0x00800000
	CKF_RW_SESSION                     = 0x00000002
	CKF_SERIAL_SESSION                 = 0x00000004
	CKF_ARRAY_ATTRIBUTE                = 0x40000000
	CKF_HW                             = 0x00000001
	CKF_ENCRYPT                        = 0x00000100
	CKF_DECRYPT                        = 0x00000200
	CKF_DIGEST                         = 0x00000400
	CKF_SIGN                           = 0x00000800
	CKF_SIGN_RECOVER                   = 0x00001000
	CKF_VERIFY                         = 0x00002000
	CKF_VERIFY_RECOVER                 = 0x00004000
	CKF_GENERATE                       = 0x00008000
	CKF_GENERATE_KEY_PAIR              = 0x00010000
	CKF_WRAP                           = 0x00020000
	CKF_UNWRAP                         = 0x00040000
	CKF_DERIVE                         = 0x00080000
	CKF_EC_F_P                         = 0x00100000
	CKF_EC_F_2M                        = 0x00200000
	CKF_EC_ECPARAMETERS                = 0x00400000
	CKF_EC_NAMEDCURVE                  = 0x00800000
	CKF_EC_UNCOMPRESS                  = 0x01000000
	CKF_EC_COMPRESS                    = 0x02000000
	CKF_EXTENSION                      = 0x80000000
	CKF_LIBRARY_CANT_CREATE_OS_THREADS = 0x00000001
	CKF_OS_LOCKING_OK                  = 0x00000002
	CKF_DONT_BLOCK                     = 1
	CKF_NEXT_OTP                       = 0x00000001
	CKF_EXCLUDE_TIME                   = 0x00000002
	CKF_EXCLUDE_COUNTER                = 0x00000004
	CKF_EXCLUDE_CHALLENGE              = 0x00000008
	CKF_EXCLUDE_PIN                    = 0x00000010
	CKF_USER_FRIENDLY_OTP              = 0x00000020
)
