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
    PATROL_STATUS_REJECTED = -1,
    PATROL_STATUS_INACTIVE = 0,
    PATROL_STATUS_ACTIVE = 1,
    PATROL_STATUS_ALL = 2,
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
    PatrolAction new_action;
    PatrolAction change_action;
    PatrolAction reject_action;
    int pin_level;
    char *notify_cmd;
    char *dialog_cmd;
    PatrolCheckFlag check;
    unsigned int dane_flags;
    time_t loaded;
} PatrolConfig;

typedef gnutls_datum_t PatrolData;
typedef gnutls_certificate_type_t PatrolChainType;

#define PATROL_DATA(_data, _size)               \
    (PatrolData) {                              \
	.data = _data,                          \
        .size = _size,                          \
    }

typedef struct PatrolRecord PatrolRecord;

struct PatrolRecord {
    /// ID of peer certificate.
    int64_t id;
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
};

void
PATROL_init ();

void
PATROL_deinit ();

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
                 uint16_t port, int64_t cert_id, int chain_result,
                 int dane_result, int dane_status, const char *app_name,
                 PatrolEvent event, PatrolAction action);

int
PATROL_get_peer_addr (int fd, int *proto,
                      char *protoname, size_t protonamelen,
                      uint16_t *port, char *addrstr);

/** Get stored certificates of a peer.
 *
 * @param host		Hostname
 * @param host_len	Length of hostname.
 * @param proto		Protocol.
 * @param proto_len	Length of protocol.
 * @param port		Port number.
 * @param wildcard	Include wildcard hostnames?
 * @param status	Certificate status.
 * @param certs		Certificates (return).
 * @param certs_len	Length of certificates (return).
 */
PatrolRC
PATROL_get_certs (const char *host, size_t host_len,
                  const char *proto, size_t proto_len, uint16_t port,
                  PatrolStatus status, bool wildcard,
                  PatrolRecord **records, size_t *records_len);

/** Get stored certificate of a peer by ID.
 */
PatrolRC
PATROL_get_cert (const char *host, size_t host_len,
                 const char *proto, size_t proto_len, uint16_t port,
                 uint64_t cert_id, PatrolRecord *record);

/** Add certificate for a peer.
 */
PatrolRC
PATROL_add_cert (const char *host, size_t host_len,
                 const char *proto, size_t proto_len,
                 uint16_t port, PatrolStatus status,
                 const PatrolData *chain, size_t chain_len,
                 const unsigned char *pin_pubkey, size_t pin_pubkey_len,
                 int64_t pin_expiry, int64_t *cert_id);

/** Set status of certificate for a peer.
 */
PatrolRC
PATROL_set_cert_status (const char *host, size_t host_len,
                        const char *proto, size_t proto_len,
                        uint16_t port, int64_t cert_id,
                        PatrolStatus status);

/** Activate a certificate for a peer.
 */
PatrolRC
PATROL_set_cert_active (const char *host, size_t host_len,
                        const char *proto, size_t proto_len,
                        uint16_t port, int64_t cert_id,
                        PatrolPinMode mode);

/** Mark certificate of a peer as seen.
 */
int
PATROL_set_cert_seen (const char *host, size_t host_len,
                      const char *proto, size_t proto_len,
                      uint16_t port, int64_t cert_id);

/** Set pinned public key for peer.
 *
 * @param host		Hostname
 * @param host_len	Length of hostname.
 * @param proto		Protocol.
 * @param proto_len	Length of protocol.
 * @param port		Port number.
 * @param pubkey	DER-encoded public key.
 * @param pubkey_len	Length of public key.
 * @param expiry	Expiry of pin.
 */
PatrolRC
PATROL_set_pin_pubkey (const char *host, size_t host_len,
                       const char *proto, size_t proto_len,
                       uint16_t port, int64_t cert_id,
                       const unsigned char *pin_pubkey, size_t pin_pubkey_len,
                       int64_t expiry);

/** Verify certificate chain against stored pin settings.
 */
PatrolVerifyRC
PATROL_verify_chain (const gnutls_datum_t *chain, size_t chain_len,
                     gnutls_certificate_type_t chain_type,
                     const char *host, size_t host_len,
                     const char *proto, size_t proto_len,
                     uint16_t port);

/** Store chain or mark it as seen.
 *
 * - If the peer does not have an entry with the end entity certificate
 *   in the chain (chain[0]), then add a new inactive entry.
 * - If an entry already exists, update its seen count and last seen values.
 */
PatrolRC
PATROL_add_or_update_cert (const PatrolData *chain, size_t chain_len,
                           gnutls_certificate_type_t chain_type,
                           const char *host, size_t host_len,
                           const char *proto, size_t proto_len,
                           uint16_t port, PatrolPinLevel pin_level, int64_t *cert_id);

/** Get pin level of pubkey from chain.
 *
 * @returns The index of certificate in the chain which contains the pubkey.
 */
int
PATROL_get_pin_level (PatrolData *chain, size_t chain_len, PatrolData pin_pubkey);

/** Set pinned pubkey from chain at level.
 */
PatrolRC
PATROL_set_pin_from_chain (const char *host, size_t host_len,
                           const char *proto, size_t proto_len,
                           uint16_t port, int64_t cert_id,
                           PatrolPinLevel pin_level,
                           PatrolData *chain, size_t chain_len);

/** @} */

#endif // PATROL_H
