#ifndef CERTPATROL_H
# define CERTPATROL_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    CERTPATROL_ERROR = -1,
    CERTPATROL_OK = 0,
    CERTPATROL_DONE = 1,
} CertPatrolRC;

typedef enum {
    CERTPATROL_PIN_EXCLUSIVE = 0,
    CERTPATROL_PIN_MULTIPLE = 1,
} CertPatrolPinMode;

typedef enum {
    CERTPATROL_PIN_TRUST_ANCHOR = -1,
    CERTPATROL_PIN_END_ENTITY = 0,
    CERTPATROL_PIN_ISSUER = 1,
} CertPatrolPinLevel;

typedef enum {
    CERTPATROL_STATUS_REJECTED = -1,
    CERTPATROL_STATUS_INACTIVE = 0,
    CERTPATROL_STATUS_ACTIVE = 1,
} CertPatrolStatus;

typedef enum {
    CERTPATROL_CMD_ACCEPT = 0,
    CERTPATROL_CMD_ACCEPT_ADD = 1,
    CERTPATROL_CMD_CONTINUE = 2,
    CERTPATROL_CMD_REJECT = 3,
} CertPatrolCmdRC;

typedef struct {
    unsigned char *data;
    unsigned int size;
} CertPatrolData;

#define CERTPATROL_DATA(_data, _size)                   \
    (CertPatrolData) {					\
	.data = _data,					\
	.size = _size,					\
    }

typedef struct CertPatrolRecord CertPatrolRecord;

struct CertPatrolRecord {
    int64_t id;		///< ID of peer certificate.
    CertPatrolStatus status;	///< Certificate status.
    int64_t first_seen;	///< Timestamp when the certificate was first seen for this peer.
    int64_t last_seen;	///< Timestamp when the certificate was last seen for this peer.
    int64_t count_seen;	///< Number of times the certificate was seen for this peer.
    CertPatrolData cert;	///< DER-encoded end entity certificate.
    CertPatrolData ca_chain;	///< DER-encoded CA chain.
    CertPatrolData pin_pubkey;	///< Pinned public key.
    int64_t pin_expiry;	///< Expiry of pin.
    CertPatrolRecord *next;
};

int
CertPatrol_get_peer_addr(int fd, int *proto,
                         char *protoname, size_t protonamelen,
                         uint16_t *port, char *addrstr);

CertPatrolCmdRC
CertPatrol_exec_cmd (const char *cmd, const char *host, const char *proto,
                     uint16_t port, int64_t cert_id, bool wait);

/**** DB functions ****/

/** Find stored certificates for a peer,
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
CertPatrolRC
CertPatrol_get_certs (const char *host, size_t host_len,
                      const char *proto, size_t proto_len, uint16_t port,
                      CertPatrolStatus status, bool wildcard,
                      CertPatrolRecord **records, size_t *records_len);

CertPatrolRC
CertPatrol_add_cert (const char *host, size_t host_len,
                     const char *proto, size_t proto_len,
                     uint16_t port, CertPatrolStatus status,
                     const CertPatrolData *chain, size_t chain_len,
                     const unsigned char *pin_pubkey, size_t pin_pubkey_len,
                     int64_t pin_expiry,
                     int64_t *cert_id);

CertPatrolRC
CertPatrol_set_cert_status (const char *host, size_t host_len,
                            const char *proto, size_t proto_len,
                            uint16_t port, int64_t cert_id,
                            int status);

CertPatrolRC
CertPatrol_set_cert_active (const char *host, size_t host_len,
                            const char *proto, size_t proto_len,
                            uint16_t port, int64_t cert_id,
                            CertPatrolPinMode mode);

int
CertPatrol_set_cert_seen (const char *host, size_t host_len,
                          const char *proto, size_t proto_len,
                          uint16_t port, int64_t cert_id);

CertPatrolRC
CertPatrol_set_pin (const char *host, size_t host_len,
                    const char *proto, size_t proto_len,
                    uint16_t port, int64_t cert_id,
                    const unsigned char *pin_pubkey, size_t pin_pubkey_len,
                    int64_t expiry);

#endif // CERTPATROL_H
