#ifndef PATROL_H
# define PATROL_H

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
} PatrolStatus;

typedef enum {
    PATROL_VERIFY_ERROR = -1,
    PATROL_VERIFY_OK = 0,
    PATROL_VERIFY_NEW = 1,
    PATROL_VERIFY_CHANGE = 2,
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
    PATROL_CMD_ACCEPT = 0,
    PATROL_CMD_ACCEPT_ADD = 1,
    PATROL_CMD_CONTINUE = 2,
    PATROL_CMD_REJECT = 3,
} PatrolCmdRC;

typedef enum {
    PATROL_CERT_UNKNOWN = 0,
    PATROL_CERT_X509 = 1,
    PATROL_CERT_OPENPGP = 2,
    PATROL_CERT_RAW = 3
} PatrolCertType;

typedef gnutls_datum_t PatrolData;

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

int
PATROL_get_peer_addr (int fd, int *proto,
                      char *protoname, size_t protonamelen,
                      uint16_t *port, char *addrstr);

PatrolCmdRC
PATROL_exec_cmd (const char *cmd, const char *host, const char *proto,
                 uint16_t port, int64_t cert_id, int chain_result,
                 int dane_result, int dane_status, const char *app_name,
                 PatrolEvent event, PatrolAction action);

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

PatrolRC
PATROL_get_cert (const char *host, size_t host_len,
                 const char *proto, size_t proto_len, uint16_t port,
                 uint64_t cert_id, PatrolRecord *record);

PatrolRC
PATROL_add_cert (const char *host, size_t host_len,
                 const char *proto, size_t proto_len,
                 uint16_t port, PatrolStatus status,
                 const PatrolData *chain, size_t chain_len,
                 const unsigned char *pin_pubkey, size_t pin_pubkey_len,
                 int64_t pin_expiry,
                 int64_t *cert_id);

PatrolRC
PATROL_set_cert_status (const char *host, size_t host_len,
                        const char *proto, size_t proto_len,
                        uint16_t port, int64_t cert_id,
                        int status);

PatrolRC
PATROL_set_cert_active (const char *host, size_t host_len,
                        const char *proto, size_t proto_len,
                        uint16_t port, int64_t cert_id,
                        PatrolPinMode mode);

int
PATROL_set_cert_seen (const char *host, size_t host_len,
                      const char *proto, size_t proto_len,
                      uint16_t port, int64_t cert_id);

PatrolRC
PATROL_set_pin (const char *host, size_t host_len,
                const char *proto, size_t proto_len,
                uint16_t port, int64_t cert_id,
                const unsigned char *pin_pubkey, size_t pin_pubkey_len,
                int64_t expiry);

PatrolRC
PATROL_set_pin_level (const char *host, size_t host_len,
                      const char *proto, size_t proto_len,
                      uint16_t port, int64_t cert_id,
                      PatrolPinLevel pin_level,
                      PatrolData *chain, size_t chain_len);

int
PATROL_get_pin_level (PatrolData *chain, size_t chain_len, PatrolData pin_pubkey);

#include <certpatrol/patrol-gnutls.h>

static inline
PatrolRC
PATROL_verify (const PatrolData *chain, size_t chain_len,
               PatrolCertType chain_type,
               PatrolRC chain_result,
               const char *host, size_t host_len,
               const char *addr, size_t addr_len,
               const char *proto, size_t proto_len,
               uint16_t port)
{
    return PATROL_GNUTLS_verify((gnutls_datum_t *)chain, chain_len, chain_type,
                                chain_result, host, host_len, addr, addr_len,
                                proto, proto_len, port);
}

#endif // PATROL_H
