#ifndef PATROL_H
# define PATROL_H

/**
 * @file certpatrol/patrol.h
 * @brief Library for public key pinning of TLS certificates
 *
 * @defgroup libcertpatrol libcertpatrol
 * @{
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gnutls/gnutls.h>

typedef enum {
    PATROL_ERROR = -1,
    PATROL_OK = 0,
    PATROL_DONE = 1,
} PatrolRC;

typedef enum {
    PATROL_PIN_EXCLUSIVE = 0,
    PATROL_PIN_MULTIPLE = 1,
} PatrolPinMode;

typedef enum {
    PATROL_PIN_TRUST_ANCHOR = -1,
    PATROL_PIN_END_ENTITY = 0,
    PATROL_PIN_ISSUER = 1,
} PatrolPinLevel;

typedef enum {
    PATROL_STATUS_INACTIVE = 1 << 0,
    PATROL_STATUS_ACTIVE   = 1 << 1,
    PATROL_STATUS_REJECTED = 1 << 2,
    PATROL_STATUS_ANY = 0xff,
} PatrolStatus;

/// The result of PATROL_verify_chain()
typedef enum {
    /// An error occured during verification.
    PATROL_VERIFY_ERROR = -1,
    /// A matching public key was found in an active entry.
    PATROL_VERIFY_OK = 0,
    /// No active or rejected entry was found for the peer.
    PATROL_VERIFY_NEW = 1,
    /// No matching public key was found in an active entry.
    PATROL_VERIFY_CHANGE = 2,
    /// A matching public key was found in a rejected entry.
    PATROL_VERIFY_REJECT = 3,
} PatrolVerifyRC;

typedef enum {
    /// Do nothing.
    PATROL_ACTION_NONE = 0,
    /// Show a notification.
    PATROL_ACTION_NOTIFY = 1,
    /// Show a dialog.
    PATROL_ACTION_DIALOG = 2,
} PatrolAction;

/// Return values of the dialog command.
typedef enum {
    /// No return value, perform configured action.
    PATROL_CMD_NONE = 0,
    /// Temporarily accept public key, but do not pin it.
    PATROL_CMD_CONTINUE = 1,
    /// Accept and pin public key.
    PATROL_CMD_ACCEPT = 2,
    /// Reject certificate.
    PATROL_CMD_REJECT = 3,
} PatrolCmdRC;

typedef enum {
    PATROL_CONFIG_NONE = 0,
    PATROL_CONFIG_UPDATE_SEEN = 1 << 0,
} PatrolConfigFlag;

typedef enum {
    PATROL_CHECK_NONE = 0,
    PATROL_CHECK_DANE = 1 << 0,
} PatrolCheckFlag;

typedef struct {
    /// New certificate for peer.
    PatrolAction new_action;
    /// Peer certificate changed to a new or inactive one.
    PatrolAction change_action;
    /// Peer certificate changed to an already rejected one.
    PatrolAction reject_action;
    /// Notify command to execute.
    char *notify_cmd;
    /// Dialog command to execute.
    char *dialog_cmd;
    /// Default pin level.
    PatrolPinLevel pin_level;
    /// Update last_seen and seen_count values.
    unsigned int flags;
    /// Check flags.
    unsigned int check_flags;
    /// DANE flags.
    unsigned int dane_flags;
    /// Timestamp when this config was loaded.
    time_t loaded;
} PatrolConfig;

#define PATROL_DEFAULT_NEW_ACTION	PATROL_ACTION_NOTIFY
#define PATROL_DEFAULT_CHANGE_ACTION	PATROL_ACTION_DIALOG
#define PATROL_DEFAULT_REJECT_ACTION	PATROL_ACTION_NOTIFY
#define PATROL_DEFAULT_NOTIFY_CMD	"certpatrol-notify"
#define PATROL_DEFAULT_DIALOG_CMD	"certpatrol-dialog"
#define PATROL_DEFAULT_PIN_LEVEL	PATROL_PIN_ISSUER
#define PATROL_DEFAULT_FLAGS		0
#define PATROL_DEFAULT_CHECK_FLAGS	PATROL_CHECK_DANE
#define PATROL_DEFAULT_DANE_FLAGS	0

typedef enum {
    PATROL_CERT_UNKNOWN = GNUTLS_CRT_UNKNOWN,
    PATROL_CERT_X509 = GNUTLS_CRT_X509,
    PATROL_CERT_OPENPGP = GNUTLS_CRT_OPENPGP,
#if GNUTLS_VERSION_MAJOR >= 3
    PATROL_CERT_RAW = GNUTLS_CRT_RAW,
#endif
} PatrolCertType;


typedef gnutls_datum_t PatrolData;

#define PATROL_DATA(_data, _size)               \
    (PatrolData) {                              \
	.data = _data,                          \
        .size = _size,                          \
    }

#define PATROL_ID_STR_LEN 36
#define PATROL_ID_STR_SIZE PATROL_ID_STR_LEN + 1
#define PATROL_ID_LEN 16

typedef unsigned char PatrolID[PATROL_ID_LEN];
typedef struct PatrolRecord PatrolRecord;

struct PatrolRecord {
    /// Certificate status.
    PatrolStatus status;
    /// Timestamp when the certificate was first seen for this peer.
    int64_t first_seen;
    /// Timestamp when the certificate was last seen for this peer.
    int64_t last_seen;
    /// Number of times the certificate was seen for this peer.
    int64_t count_seen;
    /// DER-encoded certificate chain.
    PatrolData *chain;
    /// Length of certificate chain.
    size_t chain_len;
    /// Type of certificates in the chain.
    PatrolCertType chain_type;
    /// Pinned public key.
    PatrolData pubkey;
    /// Next record.
    PatrolRecord *next;
    /// ID of peer certificate.
    PatrolID id;
};

PatrolRC
PATROL_init ();

PatrolRC
PATROL_deinit ();

PatrolRC
PATROL_init_db ();

PatrolRC
PATROL_deinit_db ();

void
PATROL_set_id (PatrolID dst, PatrolID src);

PatrolRC
PATROL_set_id_str (PatrolID dst, const char *src);

void
PATROL_get_id_str (PatrolID id, char *str);

int
PATROL_compare_ids (PatrolID a, PatrolID b);

PatrolRC
PATROL_get_config (PatrolConfig *c);

/** Check certificate chain of peer and show a dialog or notification when appropriate.
 */
PatrolRC
PATROL_check (const PatrolConfig *cfg,
              const PatrolData *chain, size_t chain_len,
              PatrolCertType chain_type,
              int chain_result, //unsigned int chain_status,
              const char *host, const char *addr, const char *proto,
              uint16_t port);

/** Execute dialog or notify command and return result.
 *
 * @param cmd		Command to execute. Either a full path, or a command in PATH.
 * @param event		Event type: new or changed certificate.
 * @param action	Action: notify or dialog. In case of a dialog,
 *                      it waits for the command to exit.
 *
 * @returns Exit status of command, or PATROL_CMD_ACCEPT for notify commands.
 */
PatrolCmdRC
PATROL_exec_cmd (const char *cmd, const char *host, const char *proto,
                 uint16_t port, PatrolID id, int chain_result,
                 int dane_result, const char *app_name,
                 PatrolVerifyRC result, PatrolAction action);

/** Get stored certificates of a peer.
 *
 * @param host		Host name.
 * @param proto		Transport protocol.
 * @param port		Port number.
 * @param wildcard	Include wildcard host names?
 * @param status	Certificate status.
 * @param certs		Certificates (return).
 * @param certs_len	Length of certificates (return).
 */
PatrolRC
PATROL_get_certs (const char *host, const char *proto, uint16_t port,
                  PatrolStatus status, bool wildcard,
                  PatrolRecord **records, size_t *records_len);

/** Get stored certificate record of a peer by ID.
 */
PatrolRC
PATROL_get_cert (const char *host, const char *proto, uint16_t port,
                 PatrolID id, PatrolStatus status, PatrolRecord *rec);

/** Add certificate for a peer if it has not yet been added.
 *
 * @return PATROL_OK on success, PATROL_DONE when a cert already exists,
 *         PATROL_ERROR on error.
 */
PatrolRC
PATROL_add_cert (const char *host, const char *proto, uint16_t port,
                 PatrolStatus status, const PatrolData *chain,
                 size_t chain_len, PatrolCertType chain_type,
                 const unsigned char *pubkey, size_t pubkey_len,
                 PatrolID *id);

/** Get status of certificate for a peer.
 */
PatrolRC
PATROL_get_cert_status (const char *host, const char *proto, uint16_t port,
                        PatrolID id, PatrolStatus *status);

/** Set status of certificate for a peer.
 */
PatrolRC
PATROL_set_cert_status (const char *host, const char *proto, uint16_t port,
                        PatrolID id, PatrolStatus status);

/** Activate a certificate for a peer.
 */
PatrolRC
PATROL_set_cert_active (const char *host, const char *proto, uint16_t port,
                        PatrolID id, PatrolPinMode mode);

/** Mark certificate of a peer as seen.
 */
int
PATROL_set_cert_seen (const char *host, const char *proto, uint16_t port,
                      PatrolID id);

/** Set pinned public key for peer.
 *
 * @param host		Host name.
 * @param proto		Transport protocol.
 * @param port		Port number.
 * @param pubkey	DER-encoded public key.
 */
PatrolRC
PATROL_set_pubkey (const char *host, const char *proto, uint16_t port,
                   PatrolID id, const unsigned char *pubkey, size_t pubkey_len);

/** Verify certificate chain against stored pinned public keys.
 */
PatrolVerifyRC
PATROL_verify_chain (const PatrolData *chain, size_t chain_len,
                     PatrolCertType chain_type,
                     const char *host, const char *proto, uint16_t port);

/** Get pin level of public key from certificate chain.
 *
 * @returns The index of certificate in the chain which contains the public key.
 */
int
PATROL_get_pin_level (const PatrolData *chain, size_t chain_len,
                      PatrolData pubkey);

/** Set pinned pubkey from chain at level.
 */
PatrolRC
PATROL_set_pubkey_from_chain (const char *host, const char *proto, uint16_t port,
                              PatrolID id, PatrolPinLevel pin_level,
                              const PatrolData *chain, size_t chain_len);
/** @} */

#endif // PATROL_H
