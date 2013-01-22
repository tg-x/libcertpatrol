#ifndef CERTPATROL_H
# define CERTPATROL_H

#include <stdlib.h>
#include <sqlite3.h>

#if defined(_MSC_VER) || defined(__BORLANDC__)
  typedef __int64 CertPatrolInt64;
  typedef unsigned __int64 CertPatrolUint64;
#else
  typedef long long int CertPatrolInt64;
  typedef unsigned long long int CertPatrolUint64;
#endif

typedef enum {
    CERTPATROL_FALSE = 0,
    CERTPATROL_TRUE  = 1,
} CertPatrolBool;

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
    CertPatrolInt64 id;		///< ID of peer certificate.
    CertPatrolStatus status;	///< Certificate status.
    CertPatrolInt64 first_seen;	///< Timestamp when the certificate was first seen for this peer.
    CertPatrolInt64 last_seen;	///< Timestamp when the certificate was last seen for this peer.
    CertPatrolInt64 count_seen;	///< Number of times the certificate was seen for this peer.
    CertPatrolData cert;	///< DER-encoded end entity certificate.
    CertPatrolData ca_chain;	///< DER-encoded CA chain.
    CertPatrolData pin_pubkey;	///< Pinned public key.
    CertPatrolInt64 pin_expiry;	///< Expiry of pin.
    CertPatrolRecord *next;
};

int
CertPatrol_get_peer_addr(int fd, int *proto,
                         char *protoname, size_t protonamelen,
                         int *port, char *addrstr);

CertPatrolCmdRC
CertPatrol_exec_cmd (const char *cmd, const char *event, const char *host,
                     const char *proto, int port,
                     CertPatrolInt64 cert_id, CertPatrolBool wait);

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
                      const char *proto, size_t proto_len, int port,
                      CertPatrolStatus status, CertPatrolBool wildcard,
                      CertPatrolRecord **records, size_t *records_len);

CertPatrolRC
CertPatrol_add_cert (const char *host, size_t host_len,
                     const char *proto, size_t proto_len,
                     int port, CertPatrolStatus status,
                     const CertPatrolData *chain, size_t chain_len,
                     const unsigned char *pin_pubkey, size_t pin_pubkey_len,
                     CertPatrolInt64 pin_expiry,
                     CertPatrolInt64 *cert_id);

CertPatrolRC
CertPatrol_set_cert_status (const char *host, size_t host_len,
                            const char *proto, size_t proto_len,
                            int port, CertPatrolInt64 cert_id, int status);

CertPatrolRC
CertPatrol_set_cert_active (const char *host, size_t host_len,
                            const char *proto, size_t proto_len,
                            int port, CertPatrolInt64 cert_id,
                            CertPatrolPinMode mode);

int
CertPatrol_set_cert_seen (const char *host, size_t host_len,
                          const char *proto, size_t proto_len,
                          int port, CertPatrolInt64 cert_id);

CertPatrolRC
CertPatrol_set_pin (const char *host, size_t host_len,
                    const char *proto, size_t proto_len,
                    int port, CertPatrolInt64 cert_id,
                    const unsigned char *pin_pubkey, size_t pin_pubkey_len,
                    CertPatrolInt64 expiry);

#endif // CERTPATROL_H
