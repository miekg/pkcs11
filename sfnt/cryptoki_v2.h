/***************************************************************************
*
*  Description: Proprietary function prototypes, typedefs, etc. for PKCS #11 API.
*
* Copyright (c) 2004-2018 SafeNet.  All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not
* be distributed or copied without written consent from SafeNet.
*
********************VERY IMPORTANT******************************************
* DO NOT ADD ANY NEW SAFENET EXTENSIONS TO ./cryptoki/cryptoki.h
* ADD ALL NEW TYPE DEFINITION EXTENSIONS TO /cryptoki/cryptoki_v2.h
* ADD ALL CA_ FUNCTION EXTENSIONS TO /cryptoki/sfnt_extensions.h
****************************************************************************/

#ifndef _CRYPTOKI_H_
#define _CRYPTOKI_H_

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************\
*                                                                            *
* Operating System/Platform linking constructs                               *
*                                                                            *
\****************************************************************************/
#if defined(VXD)
   #define CK_ENTRY
   #define CK_POINTER         *
   #pragma pack(push, 1)
#elif defined(OS_WIN32)
   #define CK_ENTRY           __declspec( dllexport )
   #define CK_POINTER         *

   #define CK_DEFINE_FUNCTION(returnType, name) \
	returnType __declspec(dllexport) name

   #define CK_DECLARE_FUNCTION(returnType, name) \
	returnType __declspec(dllexport) name

   #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
	returnType __declspec(dllexport) (* name)

   #define CK_CALLBACK_FUNCTION(returnType, name) \
	returnType (* name)

   #pragma pack(push, cryptoki, 1)

#elif defined(OS_UNIX) || defined(OS_LINUX)
   #define CK_ENTRY
   #define CK_POINTER         *

   #define CK_DEFINE_FUNCTION(returnType, name) \
	returnType name

   #define CK_DECLARE_FUNCTION(returnType, name) \
	returnType name

   #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
	returnType (* name)

   #define CK_CALLBACK_FUNCTION(returnType, name) \
	returnType (* name)

//   #pragma pack(1)
#else
   #error "Unknown platform!"
#endif

#define ulMaxSessionCount              usMaxSessionCount
#define ulSessionCount                 usSessionCount
#define ulMaxRwSessionCount            usMaxRwSessionCount
#define ulRwSessionCount               usRwSessionCount
#define ulMaxPinLen                    usMaxPinLen
#define ulMinPinLen                    usMinPinLen
#define ulDeviceError                  usDeviceError
// #define ulValueLen                     usValueLen
#define ulParameterLen                 usParameterLen
#define ulEffectiveBits                usEffectiveBits
#define ulPasswordLen                  usPasswordLen
#define sLen                           ulSaltLen
#define ulSaltLen                      usSaltLen
#define ulIteration                    usIteration



#define NULL_PTR           0

#define CK_PTR *

#include "RSA/pkcs11.h"

//Define same as ulong
#ifdef __GNUC__
typedef unsigned long int               CK_USHORT __attribute__ ((deprecated));
typedef CK_USHORT CK_PTR                CK_USHORT_PTR __attribute__ ((deprecated));
#else
typedef unsigned long int				CK_USHORT;
typedef CK_USHORT CK_PTR				CK_USHORT_PTR;
#endif

#ifndef CK_MAKE_C_VERSION
#define CK_MAKE_C_VERSION(_major, _minor)  ( ((_major) << 8) + (_minor) )
#endif

#define C_VERSION          CK_MAKE_C_VERSION(CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR) /* v2.20 decimal */

/* Serial number size is fixed, but not using a #define. Must match sizeof(CK_TOKEN_INFO.serialNumber).
 * NOTE: Assume all serial numbers are space padded and there is no trailing 0. */
#define CK_TOKEN_SERIAL_NUMBER_SIZE    16

/* some special values for certain CK_ULONG variables */
#define CK_UNAVAILABLE_INFORMATION (~0UL)
#define CK_EFFECTIVELY_INFINITE    0

#define CKU_CRYPTO_OFFICER CKU_USER
#define CKU_LIMITED_USER 0x80000001
#define CKU_LIMITED_USER_OLD 0x8000001
#define CKU_CRYPTO_USER CKU_LIMITED_USER
#define CKU_AUDIT        0x80000002
#define CKU_INVALID_USER_TYPE 0xffffffff

#define CKU_VENDOR_DEFINED    0x80000000



#define CKF_EXCLUSIVE_SESSION       0x0001
#define CKF_EXCLUSIVE_EXISTS        0x0010
#define CKF_SO_SESSION              0x8000
#define CKF_AUDIT_SESSION           0x10000

/* For internal use only */
#define CKF_VENDER_DEFINED           0x10000000
#define CKF_IGNORE_HAONLY           (CKF_VENDER_DEFINED <<3)
#define CKF_USE_APPID               (CKF_VENDER_DEFINED <<2)

/* Reset Flags */
#define CKF_RESET_LONG_BOOT         0x1

/* From ProtectServer */
#define CKF_ADMIN_TOKEN             0x10000000

/* ProtectServer Security Mode flags */
#define CKF_ENTRUST_READY			0x00000001
#define CKF_NO_CLEAR_PINS			0x00000002
#define CKF_AUTH_PROTECTION			0x00000004
#define CKF_NO_PUBLIC_CRYPTO		0x00000008
#define CKF_TAMPER_BEFORE_UPGRADE	0x00000010
#define CKF_INCREASED_SECURITY		0x00000020
#define CKF_FIPS_ALGORITHMS			0x00000040
#define CKF_FULL_SMS_ENC			0x00000080
#define CKF_FULL_SMS_SIGN			0x00000100
#define CKF_PURE_P11                0x00000200
#define CKF_DES_EVEN_PARITY_ALLOWED 0x00000400
#define CKF_USER_ECC_DP_ALLOWED     0x00000800
#define CKF_MODE_LOCKED				0x10000000

/* CKA_HSM_FEATURES flags */
#define CKF_SUPPORTS_FMS  			0x00000001  // HSM is FM Capable and enabled
#define CKF_FM_HOK_AVAIL  			0x00000002  // FM HOK Data installed
#define CKF_NO_FM_FUNCTS  			0x00000004  // FW does not support FM commands
#define CKF_STD_HOK_AVAIL  			0x00000008  // Standard HOK avail
#define CKF_FM_SMFS_ACTIV  			0x00000010  // SMFS Activated
#define CKF_STM_MODE    			0x00000100  // Secure Transport Mode
#define CKF_TAMP_MODE    			0x00000200  // Tampered

#define CKA_START_DATE_OLD_XXX     0x0083 // Kept temporarily for backward compatibility with Beta version. Use CKA_START_DATE
#define CKA_END_DATE_OLD_XXX       0x0084 // Kept temporarily for backward compatibility with Beta version. Use CKA_END_DATE

#define CKD_SHA224_KDF                 0x00000005
#define CKD_SHA224_KDF_OLD             0x80000003
#define CKD_SHA256_KDF                 0x00000006
#define CKD_SHA256_KDF_OLD             0x80000004
#define CKD_SHA384_KDF                 0x00000007
#define CKD_SHA384_KDF_OLD             0x80000005
#define CKD_SHA512_KDF                 0x00000008
#define CKD_SHA512_KDF_OLD             0x80000006
#define CKD_RIPEMD160_KDF              0x80000007

#define CKD_SHA1_NIST_KDF              0x00000012
#define CKD_SHA224_NIST_KDF            0x80000013
#define CKD_SHA256_NIST_KDF            0x80000014
#define CKD_SHA384_NIST_KDF            0x80000015
#define CKD_SHA512_NIST_KDF            0x80000016
#define CKD_RIPEMD160_NIST_KDF         0x80000017

#define CKD_SHA1_SES_KDF               0x82000000
#define CKD_SHA224_SES_KDF             0x83000000
#define CKD_SHA256_SES_KDF             0x84000000
#define CKD_SHA384_SES_KDF             0x85000000
#define CKD_SHA512_SES_KDF             0x86000000
#define CKD_RIPEMD160_SES_KDF          0x87000000
#define CKD_SES_ENC_CTR                0x00000001
#define CKD_SES_AUTH_CTR               0x00000002
#define CKD_SES_ALT_ENC_CTR            0x00000003
#define CKD_SES_ALT_AUTH_CTR           0x00000004

/* X9.42 Diffie-Hellman Key Derivation Functions */
#define CKD_SHA1_KDF_ASN1              0x00000003  // not supported
#define CKD_SHA1_KDF_CONCATENATE       0x00000004

#define CKD_SHA1_KDF_CONCATENATE_X9_42 CKD_SHA1_KDF_CONCATENATE
#define CKD_SHA1_KDF_CONCATENATE_NIST  0x80000001

#define CKD_SHA1_KDF_ASN1_X9_42        CKD_SHA1_KDF_ASN1  // not supported
#define CKD_SHA1_KDF_ASN1_NIST         0x80000002  // not supported

/* AES GCM as per PKCS11 v2.20 Ammendment 5 draft 1
   Superceded by v2.30 draft CK_GCM_PARAMS - see pkcs11t.h */
typedef struct CK_AES_GCM_PARAMS {
  CK_BYTE_PTR pIv;
  CK_ULONG ulIvLen;
  CK_ULONG ulIvBits;
  CK_BYTE_PTR pAAD;
  CK_ULONG ulAADLen;
  CK_ULONG ulTagBits;
} CK_AES_GCM_PARAMS;

typedef CK_AES_GCM_PARAMS CK_PTR CK_AES_GCM_PARAMS_PTR;

// XOR data with KDF of base key and shared data encryption mechanism parameters
typedef struct CK_XOR_BASE_DATA_KDF_PARAMS {
  CK_EC_KDF_TYPE kdf;        //KDF to use
  CK_ULONG ulSharedDataLen;  //optional shared data to add to base key data
  CK_BYTE_PTR pSharedData;
} CK_XOR_BASE_DATA_KDF_PARAMS;

typedef CK_XOR_BASE_DATA_KDF_PARAMS CK_PTR CK_XOR_BASE_DATA_KDF_PARAMS_PTR;

typedef struct CK_AES_XTS_PARAMS {
   CK_OBJECT_HANDLE hTweakKey;
   CK_BYTE cb[16];
} CK_AES_XTS_PARAMS;

typedef CK_AES_XTS_PARAMS CK_PTR CK_AES_XTS_PARAMS_PTR;

//CKK_VENDOR_DEFINED
#define CKK_KCDSA                (CKK_VENDOR_DEFINED + 0x10)
#define CKK_SEED                 (CKK_VENDOR_DEFINED + 0x11)
#define CKK_EC_EDWARDS           (CKK_VENDOR_DEFINED + 0x12)
#define CKK_EC_MONTGOMERY        (CKK_VENDOR_DEFINED + 0x13)
#define CKK_BIP32                (CKK_VENDOR_DEFINED + 0x14)

//CKA_VENDOR_DEFINED
#define CKA_CCM_PRIVATE          (CKA_VENDOR_DEFINED | 0x0001)
#define CKA_FINGERPRINT_SHA1     (CKA_VENDOR_DEFINED | 0x0002)
#define CKA_PKC_TCTRUST          (CKA_VENDOR_DEFINED | 0x0003)
#define CKA_PKC_CITS             (CKA_VENDOR_DEFINED | 0x0004)
#define CKA_OUID                 (CKA_VENDOR_DEFINED | 0x0005)
#define CKA_X9_31_GENERATED      (CKA_VENDOR_DEFINED | 0x0006)
#define CKA_PKC_ECC              (CKA_VENDOR_DEFINED | 0x0007)
#define CKA_EKM_UID              (CKA_VENDOR_DEFINED | 0x0008)

#define CKA_CHECK_VALUE_PTK      (CKA_VENDOR_DEFINED | 0x0103)

#define CKA_TOKEN_ROLE_POLICIES  (CKA_VENDOR_DEFINED | 0x0010)
#define CKA_ROLE_DESCRIPTORS     (CKA_VENDOR_DEFINED | 0x0011)
#define CKA_USER_VALUE           (CKA_VENDOR_DEFINED | 0x0012)
#define CKA_INITIALIZER          (CKA_VENDOR_DEFINED | 0x0013)
#define CKA_POLICY               (CKA_VENDOR_DEFINED | 0x0014)
#define CKA_ACTIVE               (CKA_VENDOR_DEFINED | 0x0015)

// Initially defined for role states.
#define CKA_INITIALIZED          (CKA_VENDOR_DEFINED | 0x0016)
#define CKA_PIN_TO_BE_CHANGED    (CKA_VENDOR_DEFINED | 0x0017)
#define CKA_LOCKED_OUT           (CKA_VENDOR_DEFINED | 0x0018)
#define CKA_ACTIVATED            (CKA_VENDOR_DEFINED | 0x0019)
#define CKA_HAS_DOMAIN           (CKA_VENDOR_DEFINED | 0x001A)
#define CKA_LOGIN_ATTEMPTS_LEFT  (CKA_VENDOR_DEFINED | 0x001B)
#define CKA_PRIMARY_AUTH_METHOD  (CKA_VENDOR_DEFINED | 0x001C)
#define CKA_SECONDARY_AUTH_METHOD (CKA_VENDOR_DEFINED | 0x001D)
#define CKA_ROLE_SHORT_NAME       (CKA_VENDOR_DEFINED | 0x001E)
// Generic CK_ULONG version field for any objects that need to report a version
#define CKA_VERSION              (CKA_VENDOR_DEFINED | 0x001F)

// These match the ones already defined for PTK
#define CKA_USAGE_COUNT          (CKA_VENDOR_DEFINED + 0x0101)
#define CKA_SLOT_ID              (CKA_VENDOR_DEFINED + 0x0151)
#define CKA_MAX_SESSIONS         (CKA_VENDOR_DEFINED | 0x0155)
#define CKA_MIN_PIN_LEN          (CKA_VENDOR_DEFINED | 0x0156)
#define CKA_FLAGS                (CKA_VENDOR_DEFINED | 0x0159)
#define CKA_USAGE_LIMIT          (CKA_VENDOR_DEFINED + 0x0200)

#define CKA_SECURITY_MODE        (CKA_VENDOR_DEFINED + 0x0140)
#define CKA_TRANSPORT_MODE       (CKA_VENDOR_DEFINED + 0x0141)
#define CKA_BATCH                (CKA_VENDOR_DEFINED + 0x0142)
#define CKA_HW_STATUS            (CKA_VENDOR_DEFINED + 0x0143)
#define CKA_FREE_MEM             (CKA_VENDOR_DEFINED + 0x0144)
#define CKA_TAMPER_CMD           (CKA_VENDOR_DEFINED + 0x0145)
#define CKA_DATE_OF_MANUFACTURE  (CKA_VENDOR_DEFINED + 0x0146)
#define CKA_HALT_CMD             (CKA_VENDOR_DEFINED + 0x0147)
#define CKA_APPLICATION_COUNT    (CKA_VENDOR_DEFINED + 0x0148)
#define CKA_FW_VERSION           (CKA_VENDOR_DEFINED + 0x0149)
#define CKA_RESCAN_PERIPHERALS_CMD (CKA_VENDOR_DEFINED + 0x014A)
#define CKA_RTC_AAC_ENABLED        (CKA_VENDOR_DEFINED + 0x014B)
#define CKA_RTC_AAC_GUARD_SECONDS  (CKA_VENDOR_DEFINED + 0x014C)
#define CKA_RTC_AAC_GUARD_COUNT    (CKA_VENDOR_DEFINED + 0x014D)
#define CKA_RTC_AAC_GUARD_DURATION (CKA_VENDOR_DEFINED + 0x014E)
#define CKA_HW_EXT_INFO_STR        (CKA_VENDOR_DEFINED + 0x014F)

#define CKA_TEMPERATURE_STR        (CKA_VENDOR_DEFINED + 0x0150)
#define CKA_HSM_FEATURES           (CKA_VENDOR_DEFINED + 0x0152)

#define CKA_FM_VERSION			(CKA_VENDOR_DEFINED + 0x0181)
#define CKA_MANUFACTURER		(CKA_VENDOR_DEFINED + 0x0182)
#define CKA_BUILD_DATE			(CKA_VENDOR_DEFINED + 0x0183)
#define CKA_FINGERPRINT			(CKA_VENDOR_DEFINED + 0x0184)
#define CKA_ROM_SPACE			(CKA_VENDOR_DEFINED + 0x0185)
#define CKA_RAM_SPACE			(CKA_VENDOR_DEFINED + 0x0186) /* not used */
#define CKA_FM_STATUS			(CKA_VENDOR_DEFINED + 0x0187)
#define CKA_DELETE_FM			(CKA_VENDOR_DEFINED + 0x0188)
#define CKA_FM_STARTUP_STATUS	(CKA_VENDOR_DEFINED + 0x0189)
#define CKA_FM_ID               (CKA_VENDOR_DEFINED + 0x018a)

#define CKA_GENERIC_1            (CKA_VENDOR_DEFINED + 0x1000)
#define CKA_GENERIC_2            (CKA_VENDOR_DEFINED + 0x1001)
#define CKA_GENERIC_3            (CKA_VENDOR_DEFINED + 0x1002)
#define CKA_FINGERPRINT_SHA256   (CKA_VENDOR_DEFINED + 0x1003)
#define CKA_WARNING_THRESHOLD    (CKA_VENDOR_DEFINED + 0x1004)

#define CKA_PARTITION_ATTRIBUTE  0x40000000
#define CKA_KEK_GROUP_ID         (CKA_VENDOR_DEFINED + CKA_PARTITION_ATTRIBUTE + 0x1005)
#define CKA_KEK_MAX_LIFETIME     (CKA_VENDOR_DEFINED + CKA_PARTITION_ATTRIBUTE + 0x1006)
#define CKA_KEK_ACTUAL_LIFETIME  (CKA_VENDOR_DEFINED + CKA_PARTITION_ATTRIBUTE + 0x1007)
#define CKA_KEK_MANAGEMENT_FLAGS (CKA_VENDOR_DEFINED + CKA_PARTITION_ATTRIBUTE + 0x1008)

// BIP32 attributes
#define CKA_BIP32_CHAIN_CODE         (CKA_VENDOR_DEFINED | 0x1100)
#define CKA_BIP32_VERSION_BYTES      (CKA_VENDOR_DEFINED | 0x1101)
#define CKA_BIP32_CHILD_INDEX        (CKA_VENDOR_DEFINED | 0x1102)
#define CKA_BIP32_CHILD_DEPTH        (CKA_VENDOR_DEFINED | 0x1103)
#define CKA_BIP32_ID                 (CKA_VENDOR_DEFINED | 0x1104)
#define CKA_BIP32_FINGERPRINT        (CKA_VENDOR_DEFINED | 0x1105)
#define CKA_BIP32_PARENT_FINGERPRINT (CKA_VENDOR_DEFINED | 0x1106)


// Vendor defined HW Feature objects (HW Objeects)
#define CKH_TEMPERATURE          (CKH_VENDOR_DEFINED | 0x00000001)
#define CKH_BATTERY              (CKH_VENDOR_DEFINED | 0x00000002)
#define CKH_FAN                  (CKH_VENDOR_DEFINED | 0x00000003)

#define CKM_VENDOR_DEFINED_OLD_XXX     0x00008000
#define CKM_CAST_KEY_GEN_OLD_XXX       CKM_VENDOR_DEFINED_OLD_XXX + 0        // Entrust added capabilities
#define CKM_CAST_ECB_OLD_XXX           CKM_VENDOR_DEFINED_OLD_XXX + 1        // Entrust added capabilities
#define CKM_CAST_CBC_OLD_XXX           CKM_VENDOR_DEFINED_OLD_XXX + 2        // Entrust added capabilities
#define CKM_CAST_MAC_OLD_XXX           CKM_VENDOR_DEFINED_OLD_XXX + 3        // Entrust added capabilities
#define CKM_CAST3_KEY_GEN_OLD_XXX      CKM_VENDOR_DEFINED_OLD_XXX + 4        // Entrust added capabilities
#define CKM_CAST3_ECB_OLD_XXX          CKM_VENDOR_DEFINED_OLD_XXX + 5        // Entrust added capabilities
#define CKM_CAST3_CBC_OLD_XXX          CKM_VENDOR_DEFINED_OLD_XXX + 6        // Entrust added capabilities
#define CKM_CAST3_MAC_OLD_XXX          CKM_VENDOR_DEFINED_OLD_XXX + 7        // Entrust added capabilities
#define CKM_PBE_MD2_DES_CBC_OLD_XXX    CKM_VENDOR_DEFINED_OLD_XXX + 8        // Password based encryption
#define CKM_PBE_MD5_DES_CBC_OLD_XXX    CKM_VENDOR_DEFINED_OLD_XXX + 9        // Password based encryption
#define CKM_PBE_MD5_CAST_CBC_OLD_XXX   CKM_VENDOR_DEFINED_OLD_XXX + 10       // Password based encryption
#define CKM_PBE_MD5_CAST3_CBC_OLD_XXX  CKM_VENDOR_DEFINED_OLD_XXX + 11       // Password based encryption
#define CKM_CONCATENATE_BASE_AND_KEY_OLD_XXX   CKM_VENDOR_DEFINED_OLD_XXX + 12       // SPKM & SLL added capabilities
#define CKM_CONCATENATE_KEY_AND_BASE_OLD_XXX   CKM_VENDOR_DEFINED_OLD_XXX + 13       // SPKM & SLL added capabilities
#define CKM_CONCATENATE_BASE_AND_DATA_OLD_XXX  CKM_VENDOR_DEFINED_OLD_XXX + 14       // SPKM & SLL added capabilities
#define CKM_CONCATENATE_DATA_AND_BASE_OLD_XXX  CKM_VENDOR_DEFINED_OLD_XXX + 15       // SPKM & SLL added capabilities
#define CKM_XOR_BASE_AND_DATA_OLD_XXX          CKM_VENDOR_DEFINED_OLD_XXX + 16       // SPKM & SLL added capabilities
#define CKM_EXTRACT_KEY_FROM_KEY_OLD_XXX       CKM_VENDOR_DEFINED_OLD_XXX + 17       // SPKM & SLL added capabilities
#define CKM_MD5_KEY_DERIVATION_OLD_XXX         CKM_VENDOR_DEFINED_OLD_XXX + 18       // SPKM & SLL added capabilities
#define CKM_MD2_KEY_DERIVATION_OLD_XXX         CKM_VENDOR_DEFINED_OLD_XXX + 19       // SPKM & SLL added capabilities
#define CKM_SHA1_KEY_DERIVATION_OLD_XXX        CKM_VENDOR_DEFINED_OLD_XXX + 20       // SPKM & SLL added capabilities
#define CKM_GENERIC_SECRET_KEY_GEN_OLD_XXX     CKM_VENDOR_DEFINED_OLD_XXX + 21       // Generation of secret keys
#define CKM_CAST5_KEY_GEN_OLD_XXX              CKM_VENDOR_DEFINED_OLD_XXX + 22       // Entrust added capabilities
#define CKM_CAST5_ECB_OLD_XXX                  CKM_VENDOR_DEFINED_OLD_XXX + 23       // Entrust added capabilities
#define CKM_CAST5_CBC_OLD_XXX                  CKM_VENDOR_DEFINED_OLD_XXX + 24       // Entrust added capabilities
#define CKM_CAST5_MAC_OLD_XXX                  CKM_VENDOR_DEFINED_OLD_XXX + 25       // Entrust added capabilities
#define CKM_PBE_SHA1_CAST5_CBC_OLD_XXX         CKM_VENDOR_DEFINED_OLD_XXX + 26       // Entrust added capabilities
#define CKM_KEY_TRANSLATION                    CKM_VENDOR_DEFINED_OLD_XXX + 27       // Entrust added capabilities
#define CKM_XOR_BASE_AND_KEY                   CKM_VENDOR_DEFINED + 27

#define CKM_2DES_KEY_DERIVATION                CKM_VENDOR_DEFINED_OLD_XXX + 28       // Custom Gemplus Capabilities

#define CKM_INDIRECT_LOGIN_REENCRYPT           CKM_VENDOR_DEFINED_OLD_XXX + 29       // Used for indirect login

// Old DES PBE Mechanism
#define CKM_PBE_SHA1_DES3_EDE_CBC_OLD          CKM_VENDOR_DEFINED_OLD_XXX + 30
#define CKM_PBE_SHA1_DES2_EDE_CBC_OLD          CKM_VENDOR_DEFINED_OLD_XXX + 31

// Korean algorithms
#define CKM_HAS160                             (CKM_VENDOR_DEFINED + 0x100)
#define CKM_KCDSA_KEY_PAIR_GEN                 (CKM_VENDOR_DEFINED + 0x101)
#define CKM_KCDSA_HAS160                       (CKM_VENDOR_DEFINED + 0x102)
#define CKM_SEED_KEY_GEN                       (CKM_VENDOR_DEFINED + 0x103)
#define CKM_SEED_ECB                           (CKM_VENDOR_DEFINED + 0x104)
#define CKM_SEED_CBC                           (CKM_VENDOR_DEFINED + 0x105)
#define CKM_SEED_CBC_PAD                       (CKM_VENDOR_DEFINED + 0x106)
#define CKM_SEED_MAC                           (CKM_VENDOR_DEFINED + 0x107)
#define CKM_SEED_MAC_GENERAL                   (CKM_VENDOR_DEFINED + 0x108)
#define CKM_KCDSA_SHA1                         (CKM_VENDOR_DEFINED + 0x109)
#define CKM_KCDSA_SHA224                       (CKM_VENDOR_DEFINED + 0x10A)
#define CKM_KCDSA_SHA256                       (CKM_VENDOR_DEFINED + 0x10B)
#define CKM_KCDSA_SHA384                       (CKM_VENDOR_DEFINED + 0x10C)
#define CKM_KCDSA_SHA512                       (CKM_VENDOR_DEFINED + 0x10D)
#define CKM_KCDSA_PARAMETER_GEN                (CKM_VENDOR_DEFINED + 0x10F)

// Defined prior PKCS#11. Must be redefined when PKCS#11 is updated
// Defined prior PKCS#11 and renamed to CKM_SHA224_xxx_OLD after PKCS#11 was updated
#define CKM_SHA224_RSA_PKCS_OLD                 (CKM_VENDOR_DEFINED + 0x110)
#define CKM_SHA224_RSA_PKCS_PSS_OLD             (CKM_VENDOR_DEFINED + 0x111)
#define CKM_SHA224_OLD                          (CKM_VENDOR_DEFINED + 0x112)
#define CKM_SHA224_HMAC_OLD                     (CKM_VENDOR_DEFINED + 0x113)
#define CKM_SHA224_HMAC_GENERAL_OLD             (CKM_VENDOR_DEFINED + 0x114)
#define CKM_SHA224_KEY_DERIVATION_OLD           (CKM_VENDOR_DEFINED + 0x115)

#define CKM_DES3_CTR                             (CKM_VENDOR_DEFINED + 0x116)
#define CKM_AES_CFB8                            (CKM_VENDOR_DEFINED + 0x118)
#define CKM_AES_CFB128                          (CKM_VENDOR_DEFINED + 0x119)
#define CKM_AES_OFB                             (CKM_VENDOR_DEFINED + 0x11a)
//#define CKM_AES_CTR                             (CKM_VENDOR_DEFINED + 0x11b)
// Legacy vendor defined per P11 v2.20 ammendment 5 draft 1 - adopting
// standard definition as per v2.30 - see pkcs11t.h
#define CKM_AES_GCM_2_20a5d1                    (CKM_VENDOR_DEFINED + 0x11c)
#define CKM_ARIA_CFB8                           (CKM_VENDOR_DEFINED + 0x11d)
#define CKM_ARIA_CFB128                         (CKM_VENDOR_DEFINED + 0x11e)
#define CKM_ARIA_OFB                            (CKM_VENDOR_DEFINED + 0x11f)
#define CKM_ARIA_CTR                            (CKM_VENDOR_DEFINED + 0x120)
#define CKM_ARIA_GCM                            (CKM_VENDOR_DEFINED + 0x121)

#define CKM_ECDSA_SHA224                        (CKM_VENDOR_DEFINED + 0x122)
#define CKM_ECDSA_SHA256                        (CKM_VENDOR_DEFINED + 0x123)
#define CKM_ECDSA_SHA384                        (CKM_VENDOR_DEFINED + 0x124)
#define CKM_ECDSA_SHA512                        (CKM_VENDOR_DEFINED + 0x125)
#define CKM_AES_GMAC                            (CKM_VENDOR_DEFINED + 0x126)

#define CKM_ARIA_CMAC                           (CKM_VENDOR_DEFINED + 0x128)
#define CKM_ARIA_CMAC_GENERAL                   (CKM_VENDOR_DEFINED + 0x129)
#define CKM_SEED_CMAC                           (CKM_VENDOR_DEFINED + 0x12c)
#define CKM_SEED_CMAC_GENERAL                   (CKM_VENDOR_DEFINED + 0x12d)

#define CKM_DES3_CBC_PAD_IPSEC_OLD              0x00000137
#define CKM_DES3_CBC_PAD_IPSEC                  (CKM_VENDOR_DEFINED + 0x12e)
#define CKM_AES_CBC_PAD_IPSEC_OLD               0x00001089
#define CKM_AES_CBC_PAD_IPSEC                   (CKM_VENDOR_DEFINED + 0x12f)

#define CKM_ARIA_L_ECB                          (CKM_VENDOR_DEFINED + 0x130)
#define CKM_ARIA_L_CBC                          (CKM_VENDOR_DEFINED + 0x131)
#define CKM_ARIA_L_CBC_PAD                      (CKM_VENDOR_DEFINED + 0x132)
#define CKM_ARIA_L_MAC                          (CKM_VENDOR_DEFINED + 0x133)
#define CKM_ARIA_L_MAC_GENERAL                  (CKM_VENDOR_DEFINED + 0x134)

#define CKM_SHA224_RSA_X9_31                    (CKM_VENDOR_DEFINED + 0x135)
#define CKM_SHA256_RSA_X9_31                    (CKM_VENDOR_DEFINED + 0x136)
#define CKM_SHA384_RSA_X9_31                    (CKM_VENDOR_DEFINED + 0x137)
#define CKM_SHA512_RSA_X9_31                    (CKM_VENDOR_DEFINED + 0x138)

#define CKM_SHA1_RSA_X9_31_NON_FIPS             (CKM_VENDOR_DEFINED + 0x139)
#define CKM_SHA224_RSA_X9_31_NON_FIPS           (CKM_VENDOR_DEFINED + 0x13a)
#define CKM_SHA256_RSA_X9_31_NON_FIPS           (CKM_VENDOR_DEFINED + 0x13b)
#define CKM_SHA384_RSA_X9_31_NON_FIPS           (CKM_VENDOR_DEFINED + 0x13c)
#define CKM_SHA512_RSA_X9_31_NON_FIPS           (CKM_VENDOR_DEFINED + 0x13d)
#define CKM_RSA_X9_31_NON_FIPS                  (CKM_VENDOR_DEFINED + 0x13e)

#define CKM_DSA_SHA224                          (CKM_VENDOR_DEFINED + 0x140)  //DH -moved here to keep ECDSA SHA 2 same as FW4
#define CKM_DSA_SHA256                          (CKM_VENDOR_DEFINED + 0x141)

#define CKM_RSA_FIPS_186_3_AUX_PRIME_KEY_PAIR_GEN     (CKM_VENDOR_DEFINED + 0x142)
#define CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN         (CKM_VENDOR_DEFINED + 0x143)
// Korean algorithms
#define CKM_SEED_CTR                            (CKM_VENDOR_DEFINED + 0x144)
#define CKM_KCDSA_HAS160_NO_PAD                 (CKM_VENDOR_DEFINED + 0x145)
#define CKM_KCDSA_SHA1_NO_PAD                   (CKM_VENDOR_DEFINED + 0x146)
#define CKM_KCDSA_SHA224_NO_PAD                 (CKM_VENDOR_DEFINED + 0x147)
#define CKM_KCDSA_SHA256_NO_PAD                 (CKM_VENDOR_DEFINED + 0x148)
#define CKM_KCDSA_SHA384_NO_PAD                 (CKM_VENDOR_DEFINED + 0x149)
#define CKM_KCDSA_SHA512_NO_PAD                 (CKM_VENDOR_DEFINED + 0x151)

#define CKM_DES3_X919_MAC                       (CKM_VENDOR_DEFINED + 0x150)

#define CKM_ECDSA_KEY_PAIR_GEN_W_EXTRA_BITS     (CKM_VENDOR_DEFINED + 0x160)
#define CKM_ECDSA_GBCS_SHA256                   (CKM_VENDOR_DEFINED + 0x161)

// Vendor specific key wrapping mechanisms
#define CKM_AES_KW                              (CKM_VENDOR_DEFINED + 0x170)
#define CKM_AES_KWP                             (CKM_VENDOR_DEFINED + 0x171)
#define CKM_TDEA_KW                             (CKM_VENDOR_DEFINED + 0x172)
#define CKM_TDEA_KWP                            (CKM_VENDOR_DEFINED + 0x173)

// SIM3 mechanisms
#define CKM_AES_CBC_PAD_EXTRACT                (CKM_VENDOR_DEFINED + 0x200)
#define CKM_AES_CBC_PAD_INSERT                 (CKM_VENDOR_DEFINED + 0x201)
#define CKM_AES_CBC_PAD_EXTRACT_FLATTENED      (CKM_VENDOR_DEFINED + 0x202)
#define CKM_AES_CBC_PAD_INSERT_FLATTENED       (CKM_VENDOR_DEFINED + 0x203)

// Etoken mechanisms
#define CKM_AES_CBC_PAD_EXTRACT_DOMAIN_CTRL    (CKM_VENDOR_DEFINED + 0x204)
#define CKM_AES_CBC_PAD_INSERT_DOMAIN_CTRL     (CKM_VENDOR_DEFINED + 0x205)

//defined as CKM_DES3_DERIVE_ECB in Eracom PTKC
#define CKM_PLACE_HOLDER_FOR_ERACOME_DEF_IN_SHIM (CKM_VENDOR_DEFINED + 0x502)

#define CKM_DES2_DUKPT_PIN                     (CKM_VENDOR_DEFINED + 0x611)
#define CKM_DES2_DUKPT_MAC                     (CKM_VENDOR_DEFINED + 0x612)
#define CKM_DES2_DUKPT_MAC_RESP                (CKM_VENDOR_DEFINED + 0x613)
#define CKM_DES2_DUKPT_DATA                    (CKM_VENDOR_DEFINED + 0x614)
#define CKM_DES2_DUKPT_DATA_RESP               (CKM_VENDOR_DEFINED + 0x615)

/*** EC IES mechanism (X9.63) */
#define CKM_ECIES                              (CKM_VENDOR_DEFINED + 0xA00)
#define CKM_XOR_BASE_AND_DATA_W_KDF            (CKM_VENDOR_DEFINED + 0xA01)

#define CKM_NIST_PRF_KDF                       (CKM_VENDOR_DEFINED + 0xA02)
#define CKM_PRF_KDF                            (CKM_VENDOR_DEFINED + 0xA03)
#define CKM_AES_XTS                            (CKM_VENDOR_DEFINED + 0xA04)

// SM2/SM3/SM4 mechs
#define CKM_SM3                                (CKM_VENDOR_DEFINED + 0xB01)
#define CKM_SM3_HMAC                           (CKM_VENDOR_DEFINED + 0xB02)
#define CKM_SM3_HMAC_GENERAL                   (CKM_VENDOR_DEFINED + 0xB03)
#define CKM_SM3_KEY_DERIVATION                 (CKM_VENDOR_DEFINED + 0xB04)

#define CKM_EC_EDWARDS_KEY_PAIR_GEN            (CKM_VENDOR_DEFINED + 0xC01)
#define CKM_EDDSA_NACL                         (CKM_VENDOR_DEFINED + 0xC02) // ed25519 sign/verify - NaCl compatible
#define CKM_EDDSA                              (CKM_VENDOR_DEFINED + 0xC03) // ed25519 sign/verify
#define CKM_SHA1_EDDSA_NACL                    (CKM_VENDOR_DEFINED + 0xC04)
#define CKM_SHA224_EDDSA_NACL                  (CKM_VENDOR_DEFINED + 0xC05)
#define CKM_SHA256_EDDSA_NACL                  (CKM_VENDOR_DEFINED + 0xC06)
#define CKM_SHA384_EDDSA_NACL                  (CKM_VENDOR_DEFINED + 0xC07)
#define CKM_SHA512_EDDSA_NACL                  (CKM_VENDOR_DEFINED + 0xC08)
#define CKM_SHA1_EDDSA                         (CKM_VENDOR_DEFINED + 0xC09)
#define CKM_SHA224_EDDSA                       (CKM_VENDOR_DEFINED + 0xC0A)
#define CKM_SHA256_EDDSA                       (CKM_VENDOR_DEFINED + 0xC0B)
#define CKM_SHA384_EDDSA                       (CKM_VENDOR_DEFINED + 0xC0C)
#define CKM_SHA512_EDDSA                       (CKM_VENDOR_DEFINED + 0xC0D)

#define CKM_EC_MONTGOMERY_KEY_PAIR_GEN         (CKM_VENDOR_DEFINED + 0xD01)

// SM2/SM3/SM4 mechs
#define CKM_SM3                                (CKM_VENDOR_DEFINED + 0xB01)
#define CKM_SM3_HMAC                           (CKM_VENDOR_DEFINED + 0xB02)
#define CKM_SM3_HMAC_GENERAL                   (CKM_VENDOR_DEFINED + 0xB03)
#define CKM_SM3_KEY_DERIVATION                 (CKM_VENDOR_DEFINED + 0xB04)

// BIP32 mechs
#define CKM_BIP32_MASTER_DERIVE                (CKM_VENDOR_DEFINED + 0xE00)
#define CKM_BIP32_CHILD_DERIVE                 (CKM_VENDOR_DEFINED + 0xE01)

/**
 * Mechanism parameters for CKM_ECIES.
 */
/** EC Diffie-Hellman (DH) primitive to use for shared secret derivation */
typedef CK_ULONG CK_EC_DH_PRIMITIVE;

/** EC DH primitives */
#define CKDHP_STANDARD        0x00000001
#define CKDHP_ECDH1_COFACTOR  0x00000001
#define CKDHP_MODIFIED        0x00000002 /* Not implemented */
#define CKDHP_ECDH1           0x00000003

/** Inner encryption scheme to use for ECIES */
typedef CK_ULONG CK_EC_ENC_SCHEME;

/** Inner encryption schemes */
#define CKES_XOR        0x00000001
#define CKES_DES3_CBC_PAD  0x00000002
#define CKES_AES_CBC_PAD   0x00000003
#define CKES_DES3_CBC      0x00000004
#define CKES_AES_CBC       0x00000005

/** Message Authentication Code (MAC) scheme to use for ECIES */
typedef CK_ULONG CK_EC_MAC_SCHEME;

/** MAC schemes */
#define CKMS_HMAC_SHA1        0x00000001
#define CKMS_SHA1             0x00000002
#define CKMS_HMAC_SHA224      0x00000003
#define CKMS_SHA224           0x00000004
#define CKMS_HMAC_SHA256      0x00000005
#define CKMS_SHA256           0x00000006
#define CKMS_HMAC_SHA384      0x00000007
#define CKMS_SHA384           0x00000008
#define CKMS_HMAC_SHA512      0x00000009
#define CKMS_SHA512           0x0000000a
#define CKMS_HMAC_RIPEMD160   0x0000000b
#define CKMS_RIPEMD160        0x0000000c

/** Mechanism parameter structure for ECIES */
typedef struct CK_ECIES_PARAMS
{
   /** Diffie-Hellman primitive used to derive the shared secret value */
    CK_EC_DH_PRIMITIVE dhPrimitive;

   /**   key derivation function used on the shared secret value */
    CK_EC_KDF_TYPE kdf;

   /** the length in bytes of the key derivation shared data */
    CK_ULONG ulSharedDataLen1;

   /** the key derivation padding data shared between the two parties */
    CK_BYTE_PTR pSharedData1;

   /** the encryption scheme used to transform the input data */
    CK_EC_ENC_SCHEME encScheme;

   /** the bit length of the key to use for the encryption scheme */
    CK_ULONG ulEncKeyLenInBits;

   /** the MAC scheme used for MAC generation or validation */
    CK_EC_MAC_SCHEME macScheme;

   /** the bit length of the key to use for the MAC scheme */
    CK_ULONG ulMacKeyLenInBits;

   /** the bit length of the MAC scheme output */
    CK_ULONG ulMacLenInBits;

   /** the length in bytes of the MAC shared data */
    CK_ULONG ulSharedDataLen2;

   /** the MAC padding data shared between the two parties */
    CK_BYTE_PTR pSharedData2;
} CK_ECIES_PARAMS;

typedef CK_ECIES_PARAMS CK_PTR CK_ECIES_PARAMS_PTR;



/* Parameter and values used with CKM_PRF_KDF and
 * CKM_NIST_PRF_KDF. */

typedef CK_ULONG CK_KDF_PRF_TYPE;
typedef CK_ULONG CK_KDF_PRF_ENCODING_SCHEME;

/** PRF KDF schemes */
#define CK_NIST_PRF_KDF_DES3_CMAC      0x00000001
#define CK_NIST_PRF_KDF_AES_CMAC       0x00000002
#define CK_PRF_KDF_ARIA_CMAC           0x00000003
#define CK_PRF_KDF_SEED_CMAC           0x00000004
#define CK_NIST_PRF_KDF_HMAC_SHA1      0x00000005
#define CK_NIST_PRF_KDF_HMAC_SHA224    0x00000006
#define CK_NIST_PRF_KDF_HMAC_SHA256    0x00000007
#define CK_NIST_PRF_KDF_HMAC_SHA384    0x00000008
#define CK_NIST_PRF_KDF_HMAC_SHA512    0x00000009
#define CK_PRF_KDF_HMAC_RIPEMD160      0x0000000A

/*
 * Affects the format of the fixed data passed to the PRF.
 * Scheme #3 is the one described in NIST SP 800-108.
 */
#define LUNA_PRF_KDF_ENCODING_SCHEME_1     0x00000000 // Context || 0x00 || Label || Length
#define LUNA_PRF_KDF_ENCODING_SCHEME_2     0x00000001 // Context || Label
#define LUNA_PRF_KDF_ENCODING_SCHEME_3     0x00000002 // Label || 0x00 || Context || Length
#define LUNA_PRF_KDF_ENCODING_SCHEME_4     0x00000003 // Label || Context
#define LUNA_PRF_KDF_ENCODING_SCHEME_SCP03 0x00000004
#define LUNA_PRF_KDF_ENCODING_SCHEME_HID_KD 0x00000005

typedef struct CK_KDF_PRF_PARAMS {
   CK_KDF_PRF_TYPE            prfType;
   CK_BYTE_PTR                pLabel;
   CK_ULONG                   ulLabelLen;
   CK_BYTE_PTR                pContext;
   CK_ULONG                   ulContextLen;
   CK_ULONG                   ulCounter;
   CK_KDF_PRF_ENCODING_SCHEME ulEncodingScheme;
} CK_PRF_KDF_PARAMS;

typedef CK_PRF_KDF_PARAMS CK_PTR CK_KDF_PRF_PARAMS_PTR;

/*
Additional CTR parameter structures based on CK_AES_CTR_PARAMS
PKCS has not defined these yet.
*/
#ifndef CK_SEED_CTR_PARAMS
typedef CK_AES_CTR_PARAMS CK_SEED_CTR_PARAMS;
typedef CK_SEED_CTR_PARAMS CK_PTR CK_SEED_CTR_PARAMS_PTR;
#endif

#ifndef CK_SEED_CTR_PARAMS
typedef CK_AES_CTR_PARAMS CK_ARIA_CTR_PARAMS;
typedef CK_ARIA_CTR_PARAMS CK_PTR CK_ARIA_CTR_PARAMS_PTR;
#endif

#ifndef CK_DES_CTR_PARAMS
typedef struct CK_DES_CTR_PARAMS {
    CK_ULONG ulCounterBits;
    CK_BYTE cb[8];
} CK_DES_CTR_PARAMS;
typedef CK_DES_CTR_PARAMS CK_PTR CK_DES_CTR_PARAMS_PTR;
#endif

/*
Additional GMAC parameter structures based on CK_AES_GCM_PARAMS
PKCS has not defined these yet.
*/
#ifndef CK_AES_GMAC_PARAMS
typedef CK_AES_GCM_PARAMS CK_AES_GMAC_PARAMS;
typedef CK_AES_GMAC_PARAMS CK_PTR CK_AES_GMAC_PARAMS_PTR;
#endif

// Get statistcs from HSM.
// The high and low values will need to be put together
// into a 64-bit by the caller.
typedef struct {
   CK_ULONG ulId;         // stats parameter id
   CK_ULONG ulHighValue;  // stats parameter high 32-bit value
   CK_ULONG ulLowValue;   // stats parameter low 32-bit value
} HSM_STATS_PARAMS;


//CKR_VENDOR_DEFINED

#define CKR_INSERTION_CALLBACK_NOT_SUPPORTED 0x00000141
#define CKR_FUNCTION_PARALLEL                0x0052
#define CKR_SESSION_EXCLUSIVE_EXISTS         0x00B2

#define CKR_RC_ERROR                         (CKR_VENDOR_DEFINED + 0x04)
#define CKR_CONTAINER_HANDLE_INVALID         (CKR_VENDOR_DEFINED + 0x05)
#define CKR_TOO_MANY_CONTAINERS              (CKR_VENDOR_DEFINED + 0x06)
#define CKR_USER_LOCKED_OUT                  (CKR_VENDOR_DEFINED + 0x07)
#define CKR_CLONING_PARAMETER_ALREADY_EXISTS (CKR_VENDOR_DEFINED + 0x08)
#define CKR_CLONING_PARAMETER_MISSING        (CKR_VENDOR_DEFINED + 0x09)
#define CKR_CERTIFICATE_DATA_MISSING         (CKR_VENDOR_DEFINED + 0x0a)
#define CKR_CERTIFICATE_DATA_INVALID         (CKR_VENDOR_DEFINED + 0x0b)
#define CKR_ACCEL_DEVICE_ERROR               (CKR_VENDOR_DEFINED + 0x0c)
#define CKR_WRAPPING_ERROR                   (CKR_VENDOR_DEFINED + 0x0d)
#define CKR_UNWRAPPING_ERROR                 (CKR_VENDOR_DEFINED + 0x0e)
#define CKR_MAC_MISSING                      (CKR_VENDOR_DEFINED + 0x0f)
#define CKR_DAC_POLICY_PID_MISMATCH          (CKR_VENDOR_DEFINED + 0x10)
#define CKR_DAC_MISSING                      (CKR_VENDOR_DEFINED + 0x11)
#define CKR_BAD_DAC                          (CKR_VENDOR_DEFINED + 0x12)
#define CKR_SSK_MISSING                      (CKR_VENDOR_DEFINED + 0x13)
#define CKR_BAD_MAC                          (CKR_VENDOR_DEFINED + 0x14)
#define CKR_DAK_MISSING                      (CKR_VENDOR_DEFINED + 0x15)
#define CKR_BAD_DAK                          (CKR_VENDOR_DEFINED + 0x16)
#define CKR_SIM_AUTHORIZATION_FAILED         (CKR_VENDOR_DEFINED + 0x17)
#define CKR_SIM_VERSION_UNSUPPORTED          (CKR_VENDOR_DEFINED + 0x18)
#define CKR_SIM_CORRUPT_DATA                 (CKR_VENDOR_DEFINED + 0x19)
#define CKR_USER_NOT_AUTHORIZED              (CKR_VENDOR_DEFINED + 0x1a)
#define CKR_MAX_OBJECT_COUNT_EXCEEDED        (CKR_VENDOR_DEFINED + 0x1b)
#define CKR_SO_LOGIN_FAILURE_THRESHOLD       (CKR_VENDOR_DEFINED + 0x1c)
#define CKR_SIM_AUTHFORM_INVALID             (CKR_VENDOR_DEFINED + 0x1d)
#define CKR_CITS_DAK_MISSING                 (CKR_VENDOR_DEFINED + 0x1e)
#define CKR_UNABLE_TO_CONNECT                (CKR_VENDOR_DEFINED + 0x1f)
#define CKR_PARTITION_DISABLED               (CKR_VENDOR_DEFINED + 0x20)
#define CKR_CALLBACK_ERROR                   (CKR_VENDOR_DEFINED + 0x21)
#define CKR_SECURITY_PARAMETER_MISSING       (CKR_VENDOR_DEFINED + 0x22)
#define CKR_SP_TIMEOUT                       (CKR_VENDOR_DEFINED + 0x23)
#define CKR_TIMEOUT                          (CKR_VENDOR_DEFINED + 0x24)
#define CKR_ECC_UNKNOWN_CURVE                (CKR_VENDOR_DEFINED + 0x25)
#define CKR_MTK_ZEROIZED                     (CKR_VENDOR_DEFINED + 0x26)
#define CKR_MTK_STATE_INVALID                (CKR_VENDOR_DEFINED + 0x27)
#define CKR_INVALID_ENTRY_TYPE               (CKR_VENDOR_DEFINED + 0x28)
#define CKR_MTK_SPLIT_INVALID                (CKR_VENDOR_DEFINED + 0x29)
#define CKR_HSM_STORAGE_FULL                 (CKR_VENDOR_DEFINED + 0x2a)
#define CKR_DEVICE_TIMEOUT                   (CKR_VENDOR_DEFINED + 0x2b)
#define CKR_CONTAINER_OBJECT_STORAGE_FULL    (CKR_VENDOR_DEFINED + 0x2C)
#define CKR_PED_CLIENT_NOT_RUNNING           (CKR_VENDOR_DEFINED + 0x2D)
#define CKR_PED_UNPLUGGED                    (CKR_VENDOR_DEFINED + 0x2E)
#define CKR_ECC_POINT_INVALID                (CKR_VENDOR_DEFINED + 0x2F)
#define CKR_OPERATION_NOT_ALLOWED            (CKR_VENDOR_DEFINED + 0x30)
#define CKR_LICENSE_CAPACITY_EXCEEDED        (CKR_VENDOR_DEFINED + 0x31)
#define CKR_LOG_FILE_NOT_OPEN                (CKR_VENDOR_DEFINED + 0x32)
#define CKR_LOG_FILE_WRITE_ERROR             (CKR_VENDOR_DEFINED + 0x33)
#define CKR_LOG_BAD_FILE_NAME                (CKR_VENDOR_DEFINED + 0x34)
#define CKR_LOG_FULL                         (CKR_VENDOR_DEFINED + 0x35)
#define CKR_LOG_NO_KCV                       (CKR_VENDOR_DEFINED + 0x36)
#define CKR_LOG_BAD_RECORD_HMAC              (CKR_VENDOR_DEFINED + 0x37)
#define CKR_LOG_BAD_TIME                     (CKR_VENDOR_DEFINED + 0x38)
#define CKR_LOG_AUDIT_NOT_INITIALIZED        (CKR_VENDOR_DEFINED + 0x39)
#define CKR_LOG_RESYNC_NEEDED                (CKR_VENDOR_DEFINED + 0x3A)
#define CKR_AUDIT_LOGIN_TIMEOUT_IN_PROGRESS  (CKR_VENDOR_DEFINED + 0x3B)
#define CKR_AUDIT_LOGIN_FAILURE_THRESHOLD    (CKR_VENDOR_DEFINED + 0x3C)
#define CKR_INVALID_FUF_TARGET               (CKR_VENDOR_DEFINED + 0x3D)
#define CKR_INVALID_FUF_HEADER               (CKR_VENDOR_DEFINED + 0x3E)
#define CKR_INVALID_FUF_VERSION              (CKR_VENDOR_DEFINED + 0x3F)
#define CKR_ECC_ECC_RESULT_AT_INF            (CKR_VENDOR_DEFINED + 0x40)
#define CKR_AGAIN                            (CKR_VENDOR_DEFINED + 0x41)
#define CKR_TOKEN_COPIED                     (CKR_VENDOR_DEFINED + 0x42)
#define CKR_SLOT_NOT_EMPTY                   (CKR_VENDOR_DEFINED + 0x43)
#define CKR_USER_ALREADY_ACTIVATED           (CKR_VENDOR_DEFINED + 0x44)

#define CKR_STC_NO_CONTEXT                        (CKR_VENDOR_DEFINED + 0x45)
#define CKR_STC_CLIENT_IDENTITY_NOT_CONFIGURED    (CKR_VENDOR_DEFINED + 0x46)
#define CKR_STC_PARTITION_IDENTITY_NOT_CONFIGURED (CKR_VENDOR_DEFINED + 0x47)
#define CKR_STC_DH_KEYGEN_ERROR                   (CKR_VENDOR_DEFINED + 0x48)
#define CKR_STC_CIPHER_SUITE_REJECTED             (CKR_VENDOR_DEFINED + 0x49)
#define CKR_STC_DH_KEY_NOT_FROM_SAME_GROUP        (CKR_VENDOR_DEFINED + 0x4a)
#define CKR_STC_COMPUTE_DH_KEY_ERROR              (CKR_VENDOR_DEFINED + 0x4b)
#define CKR_STC_FIRST_PHASE_KDF_ERROR             (CKR_VENDOR_DEFINED + 0x4c)
#define CKR_STC_SECOND_PHASE_KDF_ERROR            (CKR_VENDOR_DEFINED + 0x4d)
#define CKR_STC_KEY_CONFIRMATION_FAILED           (CKR_VENDOR_DEFINED + 0x4e)
#define CKR_STC_NO_SESSION_KEY                    (CKR_VENDOR_DEFINED + 0x4f)
#define CKR_STC_RESPONSE_BAD_MAC                  (CKR_VENDOR_DEFINED + 0x50)
#define CKR_STC_NOT_ENABLED                       (CKR_VENDOR_DEFINED + 0x51)
#define CKR_STC_CLIENT_HANDLE_INVALID             (CKR_VENDOR_DEFINED + 0x52)
#define CKR_STC_SESSION_INVALID                   (CKR_VENDOR_DEFINED + 0x53)
#define CKR_STC_CONTAINER_INVALID                 (CKR_VENDOR_DEFINED + 0x54)
#define CKR_STC_SEQUENCE_NUM_INVALID              (CKR_VENDOR_DEFINED + 0x55)
#define CKR_STC_NO_CHANNEL                        (CKR_VENDOR_DEFINED + 0x56)
#define CKR_STC_RESPONSE_DECRYPT_ERROR            (CKR_VENDOR_DEFINED + 0x57)
#define CKR_STC_RESPONSE_REPLAYED                 (CKR_VENDOR_DEFINED + 0X58)
#define CKR_STC_REKEY_CHANNEL_MISMATCH            (CKR_VENDOR_DEFINED + 0X59)
#define CKR_STC_RSA_ENCRYPT_ERROR                 (CKR_VENDOR_DEFINED + 0X5a)
#define CKR_STC_RSA_SIGN_ERROR                    (CKR_VENDOR_DEFINED + 0X5b)
#define CKR_STC_RSA_DECRYPT_ERROR                 (CKR_VENDOR_DEFINED + 0X5c)
#define CKR_STC_RESPONSE_UNEXPECTED_KEY           (CKR_VENDOR_DEFINED + 0X5d)
#define CKR_STC_UNEXPECTED_NONCE_PAYLOAD_SIZE     (CKR_VENDOR_DEFINED + 0X5e)
#define CKR_STC_UNEXPECTED_DH_DATA_SIZE           (CKR_VENDOR_DEFINED + 0X5f)
#define CKR_STC_OPEN_CIPHER_MISMATCH              (CKR_VENDOR_DEFINED + 0X60)
#define CKR_STC_OPEN_DHNIST_PUBKEY_ERROR          (CKR_VENDOR_DEFINED + 0X61)
#define CKR_STC_OPEN_KEY_MATERIAL_GEN_FAIL        (CKR_VENDOR_DEFINED + 0X62)
#define CKR_STC_OPEN_RESP_GEN_FAIL                (CKR_VENDOR_DEFINED + 0X63)
#define CKR_STC_ACTIVATE_MACTAG_U_VERIFY_FAIL     (CKR_VENDOR_DEFINED + 0X64)
#define CKR_STC_ACTIVATE_MACTAG_V_GEN_FAIL        (CKR_VENDOR_DEFINED + 0X65)
#define CKR_STC_ACTIVATE_RESP_GEN_FAIL            (CKR_VENDOR_DEFINED + 0X66)
#define CKR_CHALLENGE_INCORRECT                   (CKR_VENDOR_DEFINED + 0X67)
#define CKR_ACCESS_ID_INVALID                     (CKR_VENDOR_DEFINED + 0X68)
#define CKR_ACCESS_ID_ALREADY_EXISTS              (CKR_VENDOR_DEFINED + 0X69)
#define CKR_KEY_NOT_KEKABLE                       (CKR_VENDOR_DEFINED + 0x6a)
#define CKR_MECHANISM_INVALID_FOR_FP              (CKR_VENDOR_DEFINED + 0x6b)
#define CKR_OPERATION_INVALID_FOR_FP              (CKR_VENDOR_DEFINED + 0x6c)
#define CKR_SESSION_HANDLE_INVALID_FOR_FP         (CKR_VENDOR_DEFINED + 0x6d)
#define CKR_CMD_NOT_ALLOWED_HSM_IN_TRANSPORT      (CKR_VENDOR_DEFINED + 0x6e)
#define CKR_OBJECT_ALREADY_EXISTS                 (CKR_VENDOR_DEFINED + 0X6f)
#define CKR_PARTITION_ROLE_DESC_VERSION_INVALID   (CKR_VENDOR_DEFINED + 0X70)
#define CKR_PARTITION_ROLE_POLICY_VERSION_INVALID (CKR_VENDOR_DEFINED + 0X71)
#define CKR_PARTITION_ROLE_POLICY_SET_VERSION_INVALID (CKR_VENDOR_DEFINED + 0X72)
#define CKR_REKEK_KEY                             (CKR_VENDOR_DEFINED + 0X73)
#define CKR_KEK_RETRY_FAILURE                     (CKR_VENDOR_DEFINED + 0X74)
#define CKR_RNG_RESEED_TOO_EARLY                  (CKR_VENDOR_DEFINED + 0X75)
#define CKR_HSM_TAMPERED                          (CKR_VENDOR_DEFINED + 0X76)
#define CKR_CONFIG_CHANGE_ILLEGAL                 (CKR_VENDOR_DEFINED + 0x77)
#define CKR_SESSION_CONTEXT_NOT_ALLOCATED         (CKR_VENDOR_DEFINED + 0x78)
#define CKR_SESSION_CONTEXT_ALREADY_ALLOCATED     (CKR_VENDOR_DEFINED + 0x79)
#define CKR_INVALID_BL_ITB_AUTH_HEADER            (CKR_VENDOR_DEFINED + 0x7A)
#define CKR_POLICY_ID_INVALID                     (CKR_VENDOR_DEFINED + 0x7B)
#define CKR_CONFIG_ILLEGAL                        (CKR_VENDOR_DEFINED + 0x7C)
#define CKR_CONFIG_FAILS_DEPENDENCIES             (CKR_VENDOR_DEFINED + 0x7D)
#define CKR_CERTIFICATE_TYPE_INVALID              (CKR_VENDOR_DEFINED + 0x7E)

//utilization metrics
#define CKR_INVALID_UTILIZATION_METRICS           (CKR_VENDOR_DEFINED + 0x7F)
#define CKR_UTILIZATION_BIN_ID_INVALID            (CKR_VENDOR_DEFINED + 0x80)
#define CKR_UTILIZATION_COUNTER_ID_INVALID        (CKR_VENDOR_DEFINED + 0x81)
#define CKR_INVALID_SERIAL_NUM                    (CKR_VENDOR_DEFINED + 0x82)

// BIP32 errors
#define CKR_BIP32_CHILD_INDEX_INVALID             (CKR_VENDOR_DEFINED | 0x83)
#define CKR_BIP32_INVALID_HARDENED_DERIVATION     (CKR_VENDOR_DEFINED | 0x84)
#define CKR_BIP32_MASTER_SEED_LEN_INVALID         (CKR_VENDOR_DEFINED | 0x85)
#define CKR_BIP32_MASTER_SEED_INVALID             (CKR_VENDOR_DEFINED | 0x86)
#define CKR_BIP32_INVALID_KEY_PATH_LEN            (CKR_VENDOR_DEFINED | 0x87)

#define CKR_FM_ID_INVALID                         (CKR_VENDOR_DEFINED + 0x88)
#define CKR_FM_NOT_SUPPORTED                      (CKR_VENDOR_DEFINED + 0x89)
#define CKR_FM_NEVER_ENABLED                      (CKR_VENDOR_DEFINED + 0x8a)
#define CKR_FM_DISABLED                           (CKR_VENDOR_DEFINED + 0x8b)
#define CKR_FM_SMFS_INACTIVE                      (CKR_VENDOR_DEFINED + 0x8c)

// HSM restart required before the operation can be performed.
#define CKR_HSM_RESTART_REQUIRED                  (CKR_VENDOR_DEFINED + 0x8d)

#define CKR_FM_CFG_ALLOWEDFLAG_DISABLED           (CKR_VENDOR_DEFINED + 0x8e)

// These match the ones already defined for PTK
#define CKR_OBJECT_READ_ONLY                 (CKR_VENDOR_DEFINED + 0x114)
#define CKR_KEY_NOT_ACTIVE                   (CKR_VENDOR_DEFINED + 0x136)

// CKO_VENDOR_DEFINED

#define CKO_TOKEN_ROLE_POLICY_SET            (CKO_VENDOR_DEFINED + 0x0001)
#define CKO_TOKEN_ROLE_POLICY                (CKO_VENDOR_DEFINED + 0x0002)
#define CKO_TOKEN_ROLE_DESCRIPTOR            (CKO_VENDOR_DEFINED + 0x0003)
#define CKO_TOKEN_ROLE_STATE                 (CKO_VENDOR_DEFINED + 0x0004)

// Vendor defined objects ported from PTK.
#define CKO_CERTIFICATE_REQUEST     (CKO_VENDOR_DEFINED + 0x0201)
#define CKO_CRL                     (CKO_VENDOR_DEFINED + 0x0202)
#define CKO_ADAPTER                 (CKO_VENDOR_DEFINED + 0x020A)
#define CKO_SLOT                    (CKO_VENDOR_DEFINED + 0x020B)
#define CKO_FM                      (CKO_VENDOR_DEFINED + 0x020C)


// CKS_VENDOR_DEFINED: NOTE: PKCS #11 does not define vendor extensions for states.
#define CKS_RO_SO_FUNCTIONS                   5 /* still in PKCS #11 space */
#define CKS_RO_VENDOR_DEFINED                 0x80000000
#define CKS_RW_VENDOR_DEFINED                 0x90000000
#define CKS_RW_AUDIT_FUNCTIONS                (CKS_RW_VENDOR_DEFINED + 0x001)


/****************************************************************************\
*
* FASTPATH configuration flags
*
\****************************************************************************/

#define CKF_FP_NONE                                         0x00
#define CKF_FP_KEK_REPLACEMENT_ON_SESSION_KEY_DELETION      0x01
#define CKF_FP_KEK_REPLACEMENT_ON_TOKEN_KEY_DELETION        0x02
#define CKF_FP_KEK_REPLACEMENT_ON_ATTRIBUTE_CHANGE          0x04
#define CKF_FP_KEK_FLAG_ALLOW_MIXED_MODE_KEYS               0x08

/*****************************************************************************
*
* Role state
*
*****************************************************************************/

/* NOTE: These match the flag values out of the HSM. */
#define CAF_ROLE_STATE_INITIALIZED      0x01
#define CAF_ROLE_STATE_LOCKED_OUT       0x02
#define CAF_ROLE_STATE_ACTIVATED        0x04
#define CAF_ROLE_STATE_HAS_RDK          0x08
#define CAF_ROLE_STATE_PIN_CHANGE       0x10
#define CAF_ROLE_STATE_CHALLENGE_CHANGE 0x20

/* These do not; they need to be translated from values in luna2if.h. */
#define CKA_ROLE_AUTH_NONE              0x00
#define CKA_ROLE_AUTH_PASSWORD          0x01
#define CKA_ROLE_AUTH_PED               0x02
#define CKA_ROLE_AUTH_INVALID           0xFF

typedef struct {
   CK_BYTE   flags;             /* see CAF_ROLE_STATE_* values */
   CK_BYTE   loginAttemptsLeft; /* before being locked out */
   CK_BYTE   primaryAuthMech;   /* use CKA_ROLE_* values */
   CK_BYTE   secondaryAuthMech; /* CKA_ROLE_AUTH_NONE if not set. */
} CA_ROLE_STATE;

#define CA_MAX_ROLE_NAME_LEN           24
#define CA_MAX_ROLE_SHORT_NAME_LEN     4

#define CA_MAX_PRP_LABEL_LEN           24
#define CA_MAX_ROLES_PER_PARTITION     4

#define CA_MAX_PRP_PER_SET             3

/****************************************************************************\
*
* M of N
*
\****************************************************************************/
typedef struct {
   CK_ULONG    ulWeight;
   CK_BYTE_PTR pVector;
   CK_ULONG    ulVectorLen;
   } CA_MOFN_GENERATION;
typedef CA_MOFN_GENERATION * CA_MOFN_GENERATION_PTR;

typedef struct {
   CK_BYTE_PTR pVector;
   CK_ULONG    ulVectorLen;
   } CA_MOFN_ACTIVATION;
typedef CA_MOFN_ACTIVATION * CA_MOFN_ACTIVATION_PTR;

typedef struct CA_M_OF_N_STATUS {
   CK_ULONG ulID;
   CK_ULONG ulM;
   CK_ULONG ulN;
   CK_ULONG ulSecretSize;
   CK_ULONG ulFlag;         //contains 3 bits: bActive, bGenerated, and bRequired, bMofNCloneable
   } CA_MOFN_STATUS;
typedef CA_MOFN_STATUS * CA_MOFN_STATUS_PTR;


#define CAF_M_OF_N_REQUIRED                  0x00000001
#define CAF_M_OF_N_ACTIVATED                 0x00000002
#define CAF_M_OF_N_GENERATED                 0x00000004
#define CAF_M_OF_N_CLONEABLE                 0x00000008



/****************************************************************************\
*
* Custom module loading and management
*
\****************************************************************************/
typedef CK_ULONG                    CKCA_MODULE_ID;
typedef CKCA_MODULE_ID CK_POINTER   CKCA_MODULE_ID_PTR;

typedef struct CKCA_MODULE_INFO
{
   CK_ULONG   ulModuleSize;
   CK_CHAR    developerName[32];
   CK_CHAR    moduleDescription[32];
   CK_VERSION moduleVersion;
} CKCA_MODULE_INFO;
typedef CKCA_MODULE_INFO CK_POINTER   CKCA_MODULE_INFO_PTR;



#define CKCAO_Encrypt 0
#define CKCAO_Decrypt 1
#define CKCAO_Sign    2
#define CKCAO_Verify  3
#define CKCAO_Digest  4



/****************************************************************************\
*
* SafeNet High Availability Status function
*
\****************************************************************************/
// assume a client doesn't look at more than 32 Vipers
#define CK_HA_MAX_MEMBERS       32

typedef struct CK_HA_MEMBER{
   CK_CHAR     memberSerial[CK_TOKEN_SERIAL_NUMBER_SIZE + 4];
   CK_RV       memberStatus;
}CK_HA_MEMBER;

typedef struct CK_HA_STATUS{
   CK_CHAR       groupSerial[CK_TOKEN_SERIAL_NUMBER_SIZE + 4];
   CK_HA_MEMBER   memberList[CK_HA_MAX_MEMBERS];
   CK_ULONG      listSize;
}CK_HA_STATUS;

typedef CK_HA_MEMBER CK_POINTER CK_HA_MEMBER_PTR;

typedef CK_HA_STATUS  CK_POINTER CK_HA_STATE_PTR;



/****************************************************************************\
*
* SafeNet Hardware Secured Certificate functions
*
\****************************************************************************/

#define CKHSC_CERT_TYPE_TCTRUST_MAC         0x00000001
#define CKHSC_CERT_TYPE_TCTRUST_DAC         0x00000002
#define CKHSC_CERT_TYPE_CITS_ROOT           0x00000003
#define CKHSC_CERT_TYPE_CITS_MICHOC         0x00000004
#define CKHSC_CERT_TYPE_CITS_DAC            0x00000005

#define CKHSC_CERT_TYPE_ECC_MIC             0x00000006
#define CKHSC_CERT_TYPE_ECC_HOC             0x00000007
#define CKHSC_CERT_TYPE_ECC_DAC             0x00000008

#define CKHSC_CERT_TYPE_TWC                 0x00000009
#define CKHSC_CERT_TYPE_TWC2                0x0000000A
#define CKHSC_CERT_TYPE_TWC3                0x0000000B

#define CKHSC_CERT_TYPE_PEC                 0x00000010

// FM Certs
#define CKHSC_CERT_TYPE_CITS_MICHOC_FM      0x00000011
#define CKHSC_CERT_TYPE_TWC3_FM             0x00000012
#define CKHSC_CERT_TYPE_ECC_HOC_FM          0x00000013

typedef CK_ULONG CKA_SIM_AUTH_FORM;

#define CKA_SIM_NO_AUTHORIZATION 0  // no authorization needed
#define CKA_SIM_PASSWORD         1  // plain-text passwords
#define CKA_SIM_CHALLENGE        2  // challenge secrets emitted through the secure port
#define CKA_SIM_SECURE_PORT      3  // PED keys

// Portable SIM
#define CKA_SIM_PORTABLE_NO_AUTHORIZATION 4  // no authorization needed, portable
#define CKA_SIM_PORTABLE_PASSWORD         5  // plain-text passwords, portable
#define CKA_SIM_PORTABLE_CHALLENGE        6  // challenge secrets emitted through the secure port, portable
#define CKA_SIM_PORTABLE_SECURE_PORT      7  // PED keys, portable


#ifndef _TOKEN_HNDLE_DEFINED
typedef struct CT_Token *CT_TokenHndle;
#define _TOKEN_HNDLE_DEFINED /* avoid multiple definitions */
#endif

//////////////////////////////////////////////////////////////////////
// SIM3 Mechanisms
//
// Note: These are defined in the standard cryptoki mechanism list,
//       elsewhere in this file, they're copied here to ease their use
//////////////////////////////////////////////////////////////////////.

// CKM_AES_CBC_PAD_EXTRACT                (CKM_VENDOR_DEFINED + 0x200)
// CKM_AES_CBC_PAD_INSERT                 (CKM_VENDOR_DEFINED + 0x201)
// CKM_AES_CBC_PAD_EXTRACT_FLATTENED      (CKM_VENDOR_DEFINED + 0x202)
// CKM_AES_CBC_PAD_INSERT_FLATTENED       (CKM_VENDOR_DEFINED + 0x203)

//////////////////////////////////////////////////////////////////////
// SIM3 Element types
//////////////////////////////////////////////////////////////////////

#define CK_NULL_ELEMENT                 (-1)
#define CK_CRYPTOKI_ELEMENT             0x00000000
#define CK_PARAM_ELEMENT                0x00000001
#define CK_CONTAINER_ACTIVATION_ELEMENT 0x00000002
#define CK_MOFN_ACTIVATION_ELEMENT      0x00000003
#define CK_CONTAINER_ELEMENT            0x00000004

//////////////////////////////////////////////////////////////////////
// Various Cloning size definitions
//////////////////////////////////////////////////////////////////////
#define CK_CLONING_PART1_OVERHEAD   8192
#define CK_CLONING_PART2_OVERHEAD   76
#define CK_FLATTENED_OBJECT_OVERHEAD    3264

//////////////////////////////////////////////////////////////////////
// SIM3 Mechanism parameters
//////////////////////////////////////////////////////////////////////

typedef struct CK_AES_CBC_PAD_EXTRACT_PARAMS {
    CK_ULONG     ulType;                     // in
    CK_ULONG     ulHandle;                   // in
    CK_ULONG     ulDeleteAfterExtract;       // in
    CK_BYTE_PTR  pBuffer;                    // out
    CK_ULONG_PTR pulBufferLen;               // out
    //      Additional PED CF related parameters:
    CK_ULONG     ulStorage;  // in: place of HSM object storage: HSM_T, HSM_PED_T, etc. See luna2if.h .
    CK_ULONG     pedId ;     // in: PED ID: 0 (local), 1, 2,...
    CK_BYTE_PTR  pbFileName; // in: name of the file at ulStorage, where the object stored.
    // Secure backup additional parameter
    CK_ULONG     ctxID; //in: parameter specifying secure backup context handle
} CK_AES_CBC_PAD_EXTRACT_PARAMS;

typedef CK_AES_CBC_PAD_EXTRACT_PARAMS CK_POINTER CK_AES_CBC_PAD_EXTRACT_PARAMS_PTR;

typedef struct CK_AES_CBC_PAD_INSERT_PARAMS {
    CK_ULONG                        ulStorageType;              // in
    CK_ULONG                        ulContainerState;           // in
    CK_BYTE_PTR                     pBuffer;                    // in
    CK_ULONG                        ulBufferLen;                // in
    CK_ULONG_PTR                    pulType;                    // out
    CK_ULONG_PTR                    pulHandle;                  // out
    //      Additional PED CF related parameters:
    CK_ULONG     ulStorage;  // in: place of HSM object storage: HSM_T, HSM_PED_T, etc. See luna2if.h .
    CK_ULONG     pedId ;     // in: PED ID: 0 (local), 1, 2,...
    CK_BYTE_PTR  pbFileName; // in: name of the file at ulStorage, where the object stored.
    // Secure backup additional parameter
    CK_ULONG     ctxID; //in: parameter specifying secure backup context handle
} CK_AES_CBC_PAD_INSERT_PARAMS;

typedef CK_AES_CBC_PAD_INSERT_PARAMS CK_POINTER CK_AES_CBC_PAD_INSERT_PARAMS_PTR;



//////////////////////////////////////////////////////////////////////////////
// SIM3:
// List of available storage location (tokens) for keeping extracted objects.
//////////////////////////////////////////////////////////////////////////////
#define CK_STORAGE_HOST               0x00000000
#define CK_STORAGE_PED_USB_MEMORY     0x00000001
#define CK_STORAGE_HSM_USB_MEMORY     0x00000002

/****************************************************************************\
*                                                                            *
* MTK management                                                             *
*                                                                            *
\****************************************************************************/
#define CK_MTK_STATE_FLAG_RESPLIT_ABORTED    0x00000001
#define CK_MTK_STATE_FLAG_HARD_ZEROIZE       0x00000002
#define CK_MTK_STATE_FLAG_SOFT_ZEROIZE       0x00000004
#define CK_MTK_STATE_FLAG_LOCKED             0x00000008

/****************************************************************************\
*                                                                            *
* STM management                                                             *
*                                                                            *
\****************************************************************************/
#define CK_STM_STATE_FLAG_STM_TURNED_ON      0x00000004

/****************************************************************************\
*                                                                            *
* GET Types                                                                  *
*                                                                            *
\****************************************************************************/
//[...] Expose these as necessary and make sure they match LUNA ones
#define CK_GT_TSN                            0x00000003
#define CK_GT_HSM_SN                         0x0000002B
#define CK_GT_TAMPER_INFO                    0x00000054
#define CK_GT_LIVE_TAMPER_INFO               0x00000057
#define CK_GT_HW_ORIGIN_CERT_FM              0x00000059  // retrieves HOC-FM+MIC
#define CK_GT_ECC_HOC_FM                     0x0000005B
//[...]


/****************************************************************************************/



/****************************************************************************\
*
* SafeNet Cluster functions
*
\****************************************************************************/
#ifndef CK_MAX_CLUSTER_MEMBERS
#define     CK_MAX_CLUSTER_MEMBERS     8

typedef struct CK_CLUSTER_STATE {
    CK_BYTE          bMembers[CK_MAX_CLUSTER_MEMBERS][32];
    CK_ULONG         ulMemberStatus[CK_MAX_CLUSTER_MEMBERS];
} CK_CLUSTER_STATE;

typedef CK_CLUSTER_STATE CK_POINTER CK_CLUSTER_STATE_PTR;


#endif

/****************************************************************************\
*
* SafeNet PED ID constants
*
\****************************************************************************/
#define CK_PED_ID_LOCAL                 0x0000

#define CK_PED_ID_MAX                   0xFFFE

/****************************************************************************\
*
* SafeNet Usage Counter definitions and functions
*
\****************************************************************************/
#define CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_INCREMENT  0x00000001
#define CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_SET        0x00000002

/****************************************************************************\
*
* SafeNet Partition Utilization Metrics definitions and functions
*
\****************************************************************************/
#define CK_UTILIZATION_BIN_SIGN 0
#define CK_UTILIZATION_BIN_VERIFY 1
#define CK_UTILIZATION_BIN_ENCRYPT 2
#define CK_UTILIZATION_BIN_DECRYPT 3
#define CK_UTILIZATION_BIN_KEY_GENERATION 4
#define CK_UTILIZATION_BIN_KEY_DERIVATION 5
#define LUNA_UTILIZATION_BIN_MAX 6

#define CK_UTILIZATION_COUNTER_REQUESTS 0
#define LUNA_UTILIZATION_COUNTER_MAX 1
#define CK_LABLE_LENGTH_MAX (64 + 2) //2 bytes for UTF-8 terminator \0\0

typedef unsigned long long CK_ULONGLONG;

typedef CK_ULONGLONG CK_PTR CK_ULONGLONG_PTR;


typedef CK_ULONGLONG CK_UTILIZATION_COUNT;
typedef CK_UTILIZATION_COUNT CK_PTR CK_UTILIZATION_COUNT_PTR;

typedef struct CK_UTILIZATION_COUNTER {
   CK_ULONGLONG serNum;
   CK_CHAR  label[CK_LABLE_LENGTH_MAX];
   CK_ULONG ulBinId;
   CK_ULONG ulCounterId;
   CK_UTILIZATION_COUNT count;
} CK_UTILIZATION_COUNTER;

typedef CK_UTILIZATION_COUNTER CK_PTR CK_UTILIZATION_COUNTER_PTR;

/****************************************************************************\
*
* BIP32 structures and definitions
*
\****************************************************************************/
typedef struct CK_BIP32_MASTER_DERIVE_PARAMS {
   CK_ATTRIBUTE_PTR pPublicKeyTemplate;
   CK_ULONG         ulPublicKeyAttributeCount;
   CK_ATTRIBUTE_PTR pPrivateKeyTemplate;
   CK_ULONG         ulPrivateKeyAttributeCount;
   CK_OBJECT_HANDLE hPublicKey; // output parameter
   CK_OBJECT_HANDLE hPrivateKey; // output parameter
} CK_BIP32_MASTER_DERIVE_PARAMS;
typedef CK_BIP32_MASTER_DERIVE_PARAMS CK_PTR CK_BIP32_MASTER_DERIVE_PARAMS_PTR;

typedef struct CK_BIP32_CHILD_DERIVE_PARAMS {
   CK_ATTRIBUTE_PTR pPublicKeyTemplate;
   CK_ULONG         ulPublicKeyAttributeCount;
   CK_ATTRIBUTE_PTR pPrivateKeyTemplate;
   CK_ULONG         ulPrivateKeyAttributeCount;
   CK_ULONG_PTR     pulPath;
   CK_ULONG         ulPathLen;
   CK_OBJECT_HANDLE hPublicKey; // output parameter
   CK_OBJECT_HANDLE hPrivateKey; // output parameter
   CK_ULONG         ulPathErrorIndex; // output parameter
} CK_BIP32_CHILD_DERIVE_PARAMS;
typedef CK_BIP32_CHILD_DERIVE_PARAMS CK_PTR CK_BIP32_CHILD_DERIVE_PARAMS_PTR;

// BIP32 defines
#define CKG_BIP32_VERSION_MAINNET_PUB   (0x0488B21E)
#define CKG_BIP32_VERSION_MAINNET_PRIV  (0x0488ADE4)
#define CKG_BIP32_VERSION_TESTNET_PUB   (0x043587CF)
#define CKG_BIP32_VERSION_TESTNET_PRIV  (0x04358394)
#define CKG_BIP44_PURPOSE               (0x0000002C)
#define CKG_BIP44_COIN_TYPE_BTC         (0x00000000)
#define CKG_BIP44_COIN_TYPE_BTC_TESTNET (0x00000001)
#define CKG_BIP32_EXTERNAL_CHAIN        (0x00000000)
#define CKG_BIP32_INTERNAL_CHAIN        (0x00000001)
#define CKG_BIP32_MAX_SERIALIZED_LEN    (112)
#define CKG_BIP32_MAX_PATH_LEN          (255)
#define CKF_BIP32_HARDENED              (0x80000000)

// EDDSA Parameters
typedef struct CK_EDDSA_PARAMS {
    CK_BBOOL     phFlag;
    CK_ULONG     ulContextDataLen;
    CK_BYTE_PTR  pContextData;
} CK_EDDSA_PARAMS;

typedef CK_EDDSA_PARAMS CK_PTR CK_EDDSA_PARAMS_PTR;

/****************************************************************************\
*                                                                            *
*           Luna Pseudo Random Functions                                     *
*                                                                            *
\****************************************************************************/
/*#define CKP_PKCS5_PBKD2_HMAC_SHA1            0x00000001*/
#define CKP_PKCS5_PBKD2_HMAC_SM3             0x80000B01


typedef struct _CK_POLICY_INFO
{
   CK_ULONG ulID;
   CK_ULONG ulValue;
   CK_ULONG ulOffToOnDestructive;
   CK_ULONG ulOnToOffDestructive;
} CK_POLICY_INFO;

typedef CK_POLICY_INFO CK_POINTER CK_POLICY_INFO_PTR;

typedef CK_RV CK_POINTER CK_RV_PTR;

/****************************************************************************\
*
* SafeNet function list for CA_ function pointers
*
\****************************************************************************/

#ifndef DISABLE_CA_EXT

/* CK_SFNT_CA_FUNCTION_LIST is a structure holding a Cryptoki spec
 * version and pointers of appropriate types to all the
 * Cryptoki functions */
typedef struct CK_SFNT_CA_FUNCTION_LIST CK_SFNT_CA_FUNCTION_LIST;

typedef CK_SFNT_CA_FUNCTION_LIST CK_PTR CK_SFNT_CA_FUNCTION_LIST_PTR;

typedef CK_SFNT_CA_FUNCTION_LIST_PTR CK_PTR CK_SFNT_CA_FUNCTION_LIST_PTR_PTR;

#include "sfnt_extensions.h"
/* the typedefs are in a generated file. */
#include "sfnt_ext_typedef_members.h"

struct CK_SFNT_CA_FUNCTION_LIST {

  CK_VERSION    version;  /* Cryptoki version */

  /* The remainder are taken from a generated file. */
#include "sfnt_ext_list_members.h"

};

#endif // DISABLE_CA_EXT

#if defined(VXD)
   #pragma pack(pop)
#elif defined(OS_WIN32)
   #pragma pack(pop, cryptoki)
#elif defined(OS_UNIX) || defined(OS_LINUX)
//   #pragma pack
#else
   #error "Unknown platform!"
#endif

#ifdef __cplusplus
}
#endif

#if ! ( defined(OS_LINUX) || defined(OS_HPUX) || defined(OS_AIX) || defined(OS_SOLARIS) )
#pragma deprecated( CK_USHORT, CK_USHORT_PTR )
#endif // not LINUX or HPUX or AIX or Solaris (Solaris gives "unrecognized #pragma....")

#endif                /* CRYPTOKI_H_ */
