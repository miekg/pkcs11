package pkcs11

import (
	"unsafe"
)

// Generated with:
// grep CKA *t.h|grep '#define' | sed 's/^#define //' | awk ' { print $1 "=" $2 } '

type CKA_MODULUS_BITS struct{ Val uint }

func (a *CKA_MODULUS_BITS) Type() uint            { return cKA_MODULUS_BITS }
func (a *CKA_MODULUS_BITS) Value() unsafe.Pointer { return unsafe.Pointer(&a.Val) }
func (a *CKA_MODULUS_BITS) Len() uint             { return 8 }

type CKA_TOKEN struct{ Val uint }

func (a *CKA_TOKEN) Type() uint            { return cKA_TOKEN }
func (a *CKA_TOKEN) Value() unsafe.Pointer { return unsafe.Pointer(&a.Val) }
func (a *CKA_TOKEN) Len() uint             { return 8 }

const (
	cKA_CLASS                      = 0x00000000
	cKA_TOKEN                      = 0x00000001
	cKA_PRIVATE                    = 0x00000002
	cKA_LABEL                      = 0x00000003
	cKA_APPLICATION                = 0x00000010
	cKA_VALUE                      = 0x00000011
	cKA_OBJECT_ID                  = 0x00000012
	cKA_CERTIFICATE_TYPE           = 0x00000080
	cKA_ISSUER                     = 0x00000081
	cKA_SERIAL_NUMBER              = 0x00000082
	cKA_AC_ISSUER                  = 0x00000083
	cKA_OWNER                      = 0x00000084
	cKA_ATTR_TYPES                 = 0x00000085
	cKA_TRUSTED                    = 0x00000086
	cKA_CERTIFICATE_CATEGORY       = 0x00000087
	cKA_JAVA_MIDP_SECURITY_DOMAIN  = 0x00000088
	cKA_URL                        = 0x00000089
	cKA_HASH_OF_SUBJECT_PUBLIC_KEY = 0x0000008A
	cKA_HASH_OF_ISSUER_PUBLIC_KEY  = 0x0000008B
	cKA_CHECK_VALUE                = 0x00000090
	cKA_KEY_TYPE                   = 0x00000100
	cKA_SUBJECT                    = 0x00000101
	cKA_ID                         = 0x00000102
	cKA_SENSITIVE                  = 0x00000103
	cKA_ENCRYPT                    = 0x00000104
	cKA_DECRYPT                    = 0x00000105
	cKA_WRAP                       = 0x00000106
	cKA_UNWRAP                     = 0x00000107
	cKA_SIGN                       = 0x00000108
	cKA_SIGN_RECOVER               = 0x00000109
	cKA_VERIFY                     = 0x0000010A
	cKA_VERIFY_RECOVER             = 0x0000010B
	cKA_DERIVE                     = 0x0000010C
	cKA_START_DATE                 = 0x00000110
	cKA_END_DATE                   = 0x00000111
	cKA_MODULUS                    = 0x00000120
	cKA_MODULUS_BITS               = 0x00000121
	cKA_PUBLIC_EXPONENT            = 0x00000122
	cKA_PRIVATE_EXPONENT           = 0x00000123
	cKA_PRIME_1                    = 0x00000124
	cKA_PRIME_2                    = 0x00000125
	cKA_EXPONENT_1                 = 0x00000126
	cKA_EXPONENT_2                 = 0x00000127
	cKA_COEFFICIENT                = 0x00000128
	cKA_PRIME                      = 0x00000130
	cKA_SUBPRIME                   = 0x00000131
	cKA_BASE                       = 0x00000132
	cKA_PRIME_BITS                 = 0x00000133
	cKA_SUBPRIME_BITS              = 0x00000134
	cKA_SUB_PRIME_BITS             = cKA_SUBPRIME_BITS
	cKA_VALUE_BITS                 = 0x00000160
	cKA_VALUE_LEN                  = 0x00000161
	cKA_EXTRACTABLE                = 0x00000162
	cKA_LOCAL                      = 0x00000163
	cKA_NEVER_EXTRACTABLE          = 0x00000164
	cKA_ALWAYS_SENSITIVE           = 0x00000165
	cKA_KEY_GEN_MECHANISM          = 0x00000166
	cKA_MODIFIABLE                 = 0x00000170
	cKA_ECDSA_PARAMS               = 0x00000180
	cKA_EC_PARAMS                  = 0x00000180
	cKA_EC_POINT                   = 0x00000181
	cKA_SECONDARY_AUTH             = 0x00000200
	cKA_AUTH_PIN_FLAGS             = 0x00000201
	cKA_ALWAYS_AUTHENTICATE        = 0x00000202
	cKA_WRAP_WITH_TRUSTED          = 0x00000210
	cKA_WRAP_TEMPLATE              = (CKF_ARRAY_ATTRIBUTE | 0x00000211)
	cKA_UNWRAP_TEMPLATE            = (CKF_ARRAY_ATTRIBUTE | 0x00000212)
	cKA_OTP_FORMAT                 = 0x00000220
	cKA_OTP_LENGTH                 = 0x00000221
	cKA_OTP_TIME_INTERVAL          = 0x00000222
	cKA_OTP_USER_FRIENDLY_MODE     = 0x00000223
	cKA_OTP_CHALLENGE_REQUIREMENT  = 0x00000224
	cKA_OTP_TIME_REQUIREMENT       = 0x00000225
	cKA_OTP_COUNTER_REQUIREMENT    = 0x00000226
	cKA_OTP_PIN_REQUIREMENT        = 0x00000227
	cKA_OTP_COUNTER                = 0x0000022E
	cKA_OTP_TIME                   = 0x0000022F
	cKA_OTP_USER_IDENTIFIER        = 0x0000022A
	cKA_OTP_SERVICE_IDENTIFIER     = 0x0000022B
	cKA_OTP_SERVICE_LOGO           = 0x0000022C
	cKA_OTP_SERVICE_LOGO_TYPE      = 0x0000022D
	cKA_HW_FEATURE_TYPE            = 0x00000300
	cKA_RESET_ON_INIT              = 0x00000301
	cKA_HAS_RESET                  = 0x00000302
	cKA_PIXEL_X                    = 0x00000400
	cKA_PIXEL_Y                    = 0x00000401
	cKA_RESOLUTION                 = 0x00000402
	cKA_CHAR_ROWS                  = 0x00000403
	cKA_CHAR_COLUMNS               = 0x00000404
	cKA_COLOR                      = 0x00000405
	cKA_BITS_PER_PIXEL             = 0x00000406
	cKA_CHAR_SETS                  = 0x00000480
	cKA_ENCODING_METHODS           = 0x00000481
	cKA_MIME_TYPES                 = 0x00000482
	cKA_MECHANISM_TYPE             = 0x00000500
	cKA_REQUIRED_CMS_ATTRIBUTES    = 0x00000501
	cKA_DEFAULT_CMS_ATTRIBUTES     = 0x00000502
	cKA_SUPPORTED_CMS_ATTRIBUTES   = 0x00000503
	cKA_ALLOWED_MECHANISMS         = (CKF_ARRAY_ATTRIBUTE | 0x00000600)
	cKA_VENDOR_DEFINED             = 0x80000000
)
