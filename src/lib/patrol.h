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
    PATROL_STATUS_INACTIVE = 1,
    PATROL_STATUS_ACTIVE   = 1 << 1,
    PATROL_STATUS_REJECTED = 1 << 2,
    PATROL_STATUS_ANY = 0xff,
} PatrolStatus;

typedef enum {
    PATROL_VERIFY_ERROR = -1,
    PATROL_VERIFY_OK = 0,
    PATROL_VERIFY_NEW = 1,
    PATROL_VERIFY_CHANGE = 2,
    PATROL_VERIFY_REJECT = 3,
} PatrolVerifyRC;

typedef enum {
    PATROL_EVENT_NONE = 0,
    PATROL_EVENT_NEW = 1,
    PATROL_EVENT_CHANGE = 2,
    PATROL_EVENT_REJECT = 3,
} PatrolEvent;

typedef enum {
    PATROL_ACTION_NONE = 0,
    PATROL_ACTION_NOTIFY = 1,
    PATROL_ACTION_DIALOG = 2,
} PatrolAction;

typedef enum {
    PATROL_CMD_CONTINUE = 0,
    PATROL_CMD_ACCEPT = 1,
    PATROL_CMD_REJECT = 2,
} PatrolCmdRC;

typedef enum {
    PATROL_CERT_UNKNOWN = 0,
    PATROL_CERT_X509 = 1,
    PATROL_CERT_OPENPGP = 2,
    PATROL_CERT_RAW = 3
} PatrolCertType;

typedef enum {
    PATROL_CHECK_NONE = 0,
    PATROL_CHECK_DANE = 1 << 1,
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
#define PATROL_DEFAULT_CHECK_FLAGS	PATROL_CHECK_DANE
#define PATROL_DEFAULT_DANE_FLAGS	0

typedef gnutls_datum_t PatrolData;
typedef gnutls_certificate_type_t PatrolChainType;

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
    /// Pinned public key.
    PatrolData pin_pubkey;
    /// Expiry of pin.
    int64_t pin_expiry;
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
              PatrolChainType chain_type,
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
                 int dane_result, int dane_status, const char *app_name,
                 PatrolEvent event, PatrolAction action);

int
PATROL_get_peer_addr (int fd, int *proto,
                      char *protoname, size_t protonamelen,
                      uint16_t *port, char *addrstr);

/** Get stored certificates of a peer.
 *
 * @param host		Hostname
 * @param proto		Protocol.
 * @param port		Port number.
 * @param wildcard	Include wildcard hostnames?
 * @param status	Certificate status.
 * @param certs		Certificates (return).
 * @param certs_len	Length of certificates (return).
 */
PatrolRC
PATROL_get_certs (const char *host, const char *proto, uint16_t port,
                  PatrolStatus status, bool wildcard,
                  PatrolRecord **records, size_t *records_len);

/** Get stored certificate of a peer by ID.
 */
PatrolRC
PATROL_get_cert (const char *host, const char *proto, uint16_t port,
                 PatrolID id, PatrolStatus status, PatrolRecord *rec);

/** Add certificate for a peer.
 */
PatrolRC
PATROL_add_cert (const char *host, const char *proto, uint16_t port,
                 PatrolStatus status, const PatrolData *chain, size_t chain_len,
                 const unsigned char *pin_pubkey, size_t pin_pubkey_len,
                 int64_t pin_expiry, PatrolID *id);

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
 * @param host		Hostname
 * @param proto		Protocol.
 * @param port		Port number.
 * @param pubkey	DER-encoded public key.
 * @param expiry	Expiry of pin.
 */
PatrolRC
PATROL_set_pin_pubkey (const char *host, const char *proto, uint16_t port,
                       PatrolID id, const unsigned char *pin_pubkey,
                       size_t pin_pubkey_len, int64_t expiry);

/** Verify certificate chain against stored pin settings.
 */
PatrolVerifyRC
PATROL_verify_chain (const gnutls_datum_t *chain, size_t chain_len,
                     gnutls_certificate_type_t chain_type,
                     const char *host, const char *proto, uint16_t port);

/** Store chain or mark it as seen.
 *
 * - If the peer does not have an entry with the end entity certificate
 *   in the chain (chain[0]), then add a new inactive entry.
 * - If an entry already exists, update its seen count and last seen values.
 */
PatrolRC
PATROL_add_or_update_cert (const PatrolData *chain, size_t chain_len,
                           gnutls_certificate_type_t chain_type,
                           const char *host, const char *proto, uint16_t port,
                           PatrolPinLevel pin_level, PatrolID *id);

/** Get pin level of pubkey from chain.
 *
 * @returns The index of certificate in the chain which contains the pubkey.
 */
int
PATROL_get_pin_level (PatrolData *chain, size_t chain_len, PatrolData pin_pubkey);

/** Set pinned pubkey from chain at level.
 */
PatrolRC
PATROL_set_pin_from_chain (const char *host, const char *proto, uint16_t port,
                           PatrolID id, PatrolPinLevel pin_level,
                           PatrolData *chain, size_t chain_len);

/** @} */

#endif // PATROL_H
