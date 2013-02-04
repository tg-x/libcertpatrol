#define LOG_TARGET "CertPatrol-db"

#include "common.h"
#include "patrol.h"

#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>
#include <dconf.h>
#include <uuid.h>

#ifdef HAVE_GNUTLS_DANE
# include <gnutls/dane.h>
#endif

#define DIR "/system/tls/certpatrol/"

#define CFG_DIR DIR "config/"
#define CFG_KEY CFG_DIR "%s"

#define PEERS_DIR DIR "peers/"
#define PEER_DIR PEERS_DIR "%s/%s/%u/"
#define CERT_DIR PEER_DIR "%s/"
#define CERT_KEY CERT_DIR "%s"

#define PEER_FMT "%s, %s, %u"
#define CERT_FMT PEER_FMT ", %s"
#define CERT_KEY_FMT CERT_FMT ", %s"

#define ASSERT_DB                               \
    if (!db) {                                  \
        LOG_ERROR("Database not initialized");  \
        return PATROL_ERROR;                    \
    }

struct PatrolID {
    uuid_t id;
};

static DConfClient *db;

PatrolRC
PATROL_init_db ()
{
    if (db)
        return PATROL_DONE;

#if ! GLIB_CHECK_VERSION(2,36,0)
    g_type_init();
#endif

    db = dconf_client_new();

    return PATROL_OK;
}

PatrolRC
PATROL_deinit_db ()
{
    if (!db)
        return PATROL_DONE;

    dconf_client_sync(db);
    g_object_unref(db);
    db = NULL;

    return PATROL_OK;
}

static inline
void
set_id (PatrolID dst, PatrolID src)
{
    memcpy(dst, src, PATROL_ID_LEN);
}

static inline
PatrolRC
set_id_str (PatrolID dst, const char *src)
{
    return 0 == uuid_parse(src, dst)
        ? PATROL_OK : PATROL_ERROR;
}

static inline
void
get_id_str (PatrolID id, char *str)
{
    uuid_unparse_lower(id, str);
}

static inline
int
compare_ids (PatrolID a, PatrolID b)
{
    return uuid_compare(a, b);
}

void
PATROL_set_id (PatrolID dst, PatrolID src)
{
    set_id(dst, src);
}

PatrolRC
PATROL_set_id_str (PatrolID dst, const char *src)
{
    return set_id_str(dst, src);
}

void
PATROL_get_id_str (PatrolID id, char *str)
{
    get_id_str(id, str);
}

int
PATROL_compare_ids (PatrolID a, PatrolID b)
{
    return compare_ids(a, b);
}

static inline
GVariant *
read_val (const char *host, const char *proto, uint16_t port,
          PatrolID id, const char *key)
{
    char id_str[PATROL_ID_STR_SIZE];
    get_id_str(id, id_str);
    LOG_DEBUG(">> read_val: " CERT_KEY_FMT, host, proto, port, id_str, key);

    gchar *k = g_strdup_printf(CERT_KEY, host, proto, port, id_str, key);
    GVariant *val = dconf_client_read(db, k);

    g_free(k);
    return val;
}

static inline
GVariant *
read_val_type (const char *host, const char *proto, uint16_t port,
               PatrolID id, const char *key, const GVariantType *type)
{
    char id_str[PATROL_ID_STR_SIZE];
    get_id_str(id, id_str);
    LOG_DEBUG(">> read_val_type: " CERT_KEY_FMT, host, proto, port, id_str, key);

    gchar *k = g_strdup_printf(CERT_KEY, host, proto, port, id_str, key);
    GVariant *val = dconf_client_read(db, k);
    g_free(k);

    if (val && !g_variant_is_of_type(val, type)) {
        g_variant_unref(val);
        return NULL;
    }

    return val;
}

static inline
GVariant *
read_cfg_val (const char *key, const GVariantType *type)
{
    LOG_DEBUG(">> read_cfg_val: %s", key);

    gchar *k = g_strdup_printf(CFG_KEY, key);
    GVariant *val = dconf_client_read(db, k);
    g_free(k);

    if (val && !g_variant_is_of_type(val, type)) {
        g_variant_unref(val);
        return NULL;
    }

    return val;
}

static inline
gboolean
write_val (const char *host, const char *proto, uint16_t port,
           PatrolID id, const char *key, GVariant *val)
{
    char id_str[PATROL_ID_STR_SIZE];
    get_id_str(id, id_str);
    LOG_DEBUG(">> write_val: " CERT_KEY_FMT, host, proto, port, id_str, key);

    gchar *k = g_strdup_printf(CERT_KEY, host, proto, port, id_str, key);
    gboolean ret = dconf_client_write_fast(db, k, val, NULL);

    g_free(k);
    return ret;
}

static inline
gboolean
write_cfg_val (const char *key, GVariant *val)
{
    LOG_DEBUG(">> write_cfg_val: %s", key);

    gchar *k = g_strdup_printf(CFG_KEY, key);
    gboolean ret = dconf_client_write_fast(db, k, val, NULL);

    g_free(k);
    return ret;
}

static inline
void
set_val (DConfChangeset *ch, const char *host, const char *proto,
         uint16_t port, PatrolID id, const char *key, GVariant *val)
{
    char id_str[PATROL_ID_STR_SIZE];
    get_id_str(id, id_str);
    LOG_DEBUG(">> set_val: " CERT_KEY_FMT, host, proto, port, id_str, key);

    gchar *k = g_strdup_printf(CERT_KEY, host, proto, port, id_str, key);
    dconf_changeset_set(ch, k, val);

    g_free(k);
}

static inline
void
set_cfg_val (DConfChangeset *ch, const char *key, GVariant *val)
{
    LOG_DEBUG(">> set_cfg_val: %s", key);

    gchar *k = g_strdup_printf(CFG_KEY, key);
    dconf_changeset_set(ch, k, val);

    g_free(k);
}

PatrolRC
PATROL_get_config (PatrolConfig *c)
{
    LOG_DEBUG(">> get_config");
    ASSERT_DB;

    c->new_action = PATROL_DEFAULT_NEW_ACTION;
    c->change_action = PATROL_DEFAULT_CHANGE_ACTION;
    c->reject_action = PATROL_DEFAULT_REJECT_ACTION;
    c->notify_cmd = PATROL_DEFAULT_NOTIFY_CMD;
    c->dialog_cmd = PATROL_DEFAULT_DIALOG_CMD;
    c->pin_level = PATROL_DEFAULT_PIN_LEVEL;
    c->check_flags = PATROL_DEFAULT_CHECK_FLAGS;
    c->dane_flags = PATROL_DEFAULT_DANE_FLAGS;

    GVariant *val;

    if ((val = read_cfg_val("new-action", G_VARIANT_TYPE_UINT32))) {
        c->new_action = g_variant_get_uint32(val);
        g_variant_unref(val);
    }

    if ((val = read_cfg_val("change-action", G_VARIANT_TYPE_UINT32))) {
        c->change_action = g_variant_get_uint32(val);
        g_variant_unref(val);
    }

    if ((val = read_cfg_val("reject-action", G_VARIANT_TYPE_UINT32))) {
        c->reject_action = g_variant_get_uint32(val);
        g_variant_unref(val);
    }

    if ((val = read_cfg_val("notify-cmd", G_VARIANT_TYPE_STRING))) {
        c->notify_cmd = g_variant_dup_string(val, NULL);
        g_variant_unref(val);
    }

    if ((val = read_cfg_val("dialog-cmd", G_VARIANT_TYPE_STRING))) {
        c->notify_cmd = g_variant_dup_string(val, NULL);
        g_variant_unref(val);
    }

    if ((val = read_cfg_val("pin-level", G_VARIANT_TYPE_INT32))) {
        c->reject_action = g_variant_get_int32(val);
        g_variant_unref(val);
    }

    if ((val = read_cfg_val("check-dane", G_VARIANT_TYPE_BOOLEAN))) {
        if (g_variant_get_boolean(val))
            c->check_flags |= PATROL_CHECK_DANE;
        g_variant_unref(val);
    }

    if ((val = read_cfg_val("dane-ignore-local-resolver", G_VARIANT_TYPE_BOOLEAN))) {
        if (g_variant_get_boolean(val))
            c->dane_flags |= DANE_F_IGNORE_LOCAL_RESOLVER;
        g_variant_unref(val);
    }

    c->loaded = time(NULL);
    return PATROL_OK;
}

PatrolRC
PATROL_set_config (PatrolConfig *c)
{
    LOG_DEBUG(">> set_config");
    ASSERT_DB;

    DConfChangeset *ch = dconf_changeset_new();

    set_cfg_val(ch, "new-action", g_variant_new_uint32(c->new_action));
    set_cfg_val(ch, "change-action", g_variant_new_uint32(c->change_action));
    set_cfg_val(ch, "reject-action", g_variant_new_uint32(c->reject_action));
    set_cfg_val(ch, "notify-cmd", g_variant_new_string(c->notify_cmd));
    set_cfg_val(ch, "dialog-cmd", g_variant_new_string(c->dialog_cmd));
    set_cfg_val(ch, "pin-level", g_variant_new_int32(c->pin_level));
    set_cfg_val(ch, "check-dane",
                g_variant_new_boolean(c->check_flags & PATROL_CHECK_DANE));
    set_cfg_val(ch, "dane-ignore-local-resolver",
                g_variant_new_boolean(c->dane_flags & DANE_F_IGNORE_LOCAL_RESOLVER));

    PatrolRC ret = PATROL_OK;
    if (!dconf_client_change_fast(db, ch, NULL))
        ret = PATROL_ERROR;

    dconf_changeset_unref(ch);
    return ret;
}

PatrolRC
PATROL_get_cert (const char *host, const char *proto, uint16_t port,
                 PatrolID id, unsigned int status, PatrolRecord *rec)
{
#if DEBUG
    char id_str[PATROL_ID_STR_SIZE];
    get_id_str(id, id_str);
    LOG_DEBUG(">> get_cert: " CERT_FMT, host, proto, port, id_str);
#endif
    ASSERT_DB;

    *rec = (PatrolRecord) { 0 };

    PatrolRC ret = PATROL_get_cert_status(host, proto, port, id, &rec->status);
    if (ret != PATROL_OK)
        return ret;

    if (!(status & rec->status))
        return PATROL_DONE;

    set_id(rec->id, id);
  
    GVariant *val;
    val = read_val_type(host, proto, port, id,
                        "first_seen", G_VARIANT_TYPE_INT64);
    if (val) {
        rec->first_seen = g_variant_get_int64(val);
        g_variant_unref(val);
    }

    val = read_val_type(host, proto, port, id,
                        "last_seen", G_VARIANT_TYPE_INT64);
    if (val) {
        rec->last_seen = g_variant_get_int64(val);
        g_variant_unref(val);
    }

    val = read_val_type(host, proto, port, id,
                        "count_seen", G_VARIANT_TYPE_INT64);
    if (val) {
        rec->count_seen = g_variant_get_int64(val);
        g_variant_unref(val);
    }

    val = read_val_type(host, proto, port, id,
                        "chain", G_VARIANT_TYPE_ARRAY);
    if (val) {
        rec->chain_len = g_variant_n_children(val);
        rec->chain = malloc(rec->chain_len * sizeof(PatrolData));
        for (size_t i = 0; i < rec->chain_len; i++) {
            GVariant *crt = g_variant_get_child_value(val, i);
            if (crt) {
                rec->chain[i].size = g_variant_get_size(crt);
                rec->chain[i].data = malloc(rec->chain[i].size);
                memcpy(rec->chain[i].data, g_variant_get_data(crt),
                       rec->chain[i].size);
                g_variant_unref(crt);
            }
        }
        g_variant_unref(val);
    }

    val = read_val(host, proto, port, id, "pin_pubkey");
    if (val) {
        rec->pin_pubkey.size = g_variant_get_size(val);
        rec->pin_pubkey.data = malloc(rec->pin_pubkey.size);
        memcpy(rec->pin_pubkey.data, g_variant_get_data(val),
               rec->pin_pubkey.size);
        g_variant_unref(val);
    }

    val = read_val_type(host, proto, port, id,
                        "pin_expiry", G_VARIANT_TYPE_INT64);
    if (val) {
        rec->pin_expiry = g_variant_get_int64(val);
        g_variant_unref(val);
    }

    return PATROL_OK;
}

PatrolRC
PATROL_get_certs (const char *host, const char *proto, uint16_t port,
                  unsigned int status, bool wildcard,
                  PatrolRecord **records, size_t *records_len)
{
    LOG_DEBUG(">> get_certs: " PEER_FMT ", %d, %u",
              host, proto, port, status, wildcard);
    ASSERT_DB;

    gint i, len = 0;
    gchar *peer_dir = g_strdup_printf(PEER_DIR, host, proto, port);
    gchar **keys = dconf_client_list(db, peer_dir, &len);

    *records_len = 0;
    *records = NULL;
    PatrolRecord r, *rec = NULL;

    for (i = 0; i < len; i++) {
        PatrolID id;
        size_t key_len = strlen(keys[i]);
        if (key_len != PATROL_ID_STR_LEN + 1)
            continue;
        keys[i][PATROL_ID_STR_LEN] = '\0';
        if (PATROL_OK != set_id_str(id, keys[i]))
            continue;
        switch (PATROL_get_cert(host, proto, port, id, status, &r)) {
        case PATROL_OK:
            if (!rec) {
                rec = *records = malloc(sizeof(PatrolRecord));
            } else {
                rec = rec->next = malloc(sizeof(PatrolRecord));
            }
            memcpy(rec, &r, sizeof(PatrolRecord));
            (*records_len)++;
            break;

        case PATROL_DONE:
            break;

        default:
            return PATROL_ERROR;
        }
    }

    LOG_DEBUG("<< get_certs: %zu", *records_len);
    return *records_len ? PATROL_OK : PATROL_DONE;
}

PatrolRC
PATROL_find_cert (const char *host, const char *proto, uint16_t port,
                  const unsigned char *cert, size_t cert_len, PatrolID *id)
{
    LOG_DEBUG(">> find_cert: " PEER_FMT, host, proto, port);
    ASSERT_DB;

    gint i, len = 0;
    gchar *peer_dir = g_strdup_printf(PEER_DIR, host, proto, port);
    gchar **keys = dconf_client_list(db, peer_dir, &len);

    PatrolRC ret = PATROL_DONE;
    for (i = 0; i < len && ret != PATROL_OK; i++) {
        size_t key_len = strlen(keys[i]);
        if (key_len != PATROL_ID_STR_LEN + 1)
            continue;
        keys[i][PATROL_ID_STR_LEN] = '\0';
        if (PATROL_OK != set_id_str(*id, keys[i]))
            continue;
        gchar *key = g_strdup_printf("%s%s/chain", peer_dir, keys[i]);
        GVariant *chain = dconf_client_read(db, key);
        g_free(key);
        if (chain) {
            GVariant *crt = g_variant_get_child_value(chain, 0);
            if (crt) {
                gsize size = g_variant_get_size(crt);
                const gchar *data = g_variant_get_data(crt);
                if (size == cert_len && 0 == memcmp(data, cert, cert_len)) {
                    ret = PATROL_OK;
                }
                g_variant_unref(crt);
            }
        }
        g_variant_unref(chain);
    }

    g_free(peer_dir);
    g_free(keys);

    LOG_DEBUG("<< find_cert: %d", ret);
    return ret;
}

PatrolRC
PATROL_add_cert (const char *host, const char *proto,
                 uint16_t port, PatrolStatus status,
                 const PatrolData *chain, size_t chain_len,
                 const unsigned char *pin_pubkey, size_t pin_pubkey_len,
                 int64_t pin_expiry, PatrolID *id)
{
    LOG_DEBUG(">> add_cert: " PEER_FMT ", %d, %zu, %zu, %" PRId64,
              host, proto, port, status,
              chain_len, pin_pubkey_len, pin_expiry);
    ASSERT_DB;
    if (!chain_len)
        return PATROL_ERROR;

    uuid_clear(*id);

    switch (PATROL_find_cert(host, proto, port, chain[0].data,
                             chain[0].size, id)) {
    case PATROL_DONE: // not found, add new
        uuid_generate(*id);

        DConfChangeset *ch = dconf_changeset_new();

        set_val(ch, host, proto, port, *id, "status",
                g_variant_new_uint32(status));

        time_t now = time(NULL);
        set_val(ch, host, proto, port, *id, "first_seen",
                g_variant_new_int64(now));

        set_val(ch, host, proto, port, *id, "last_seen",
                g_variant_new_int64(now));

        set_val(ch, host, proto, port, *id, "count_seen",
                g_variant_new_uint64(1));

        set_val(ch, host, proto, port, *id, "pin_expiry",
                g_variant_new_int64(pin_expiry));

        set_val(ch, host, proto, port, *id, "pin_pubkey",
                g_variant_new_from_data(G_VARIANT_TYPE_BYTESTRING,
                                        pin_pubkey, pin_pubkey_len,
                                        TRUE, NULL, NULL));

        GVariant **items = g_new0(GVariant *, chain_len);
        for (size_t i = 0; i < chain_len; i++)
            items[i] = g_variant_new_from_data(G_VARIANT_TYPE_BYTESTRING,
                                               chain[i].data, chain[i].size,
                                               TRUE, NULL, NULL);
        set_val(ch, host, proto, port, *id, "chain",
                g_variant_new_array(NULL, items, chain_len));
        g_free(items);

        PatrolRC ret = PATROL_OK;
        if (!dconf_client_change_fast(db, ch, NULL))
            ret = PATROL_ERROR;

        dconf_changeset_unref(ch);
        return ret;

    case PATROL_OK:
        return PATROL_DONE;

    default:
        return PATROL_ERROR;
    }
}


PatrolRC
PATROL_get_cert_status (const char *host, const char *proto, uint16_t port,
                        PatrolID id, PatrolStatus *status)
{
#if DEBUG
    char id_str[PATROL_ID_STR_SIZE];
    get_id_str(id, id_str);
    LOG_DEBUG(">> get_cert_status: " CERT_FMT, host, proto, port, id_str);
#endif
    ASSERT_DB;

    GVariant *val = read_val(host, proto, port, id, "status");
    if (!val)
        return PATROL_DONE;

    if (!g_variant_is_of_type(val, G_VARIANT_TYPE_UINT32)) {
        g_variant_unref(val);
        return PATROL_ERROR;
    }

    if (status)
        *status = g_variant_get_uint32(val);

    g_variant_unref(val);
    return PATROL_OK;
}

PatrolRC
PATROL_set_cert_status (const char *host, const char *proto, uint16_t port,
                        PatrolID id, PatrolStatus status)
{
#if DEBUG
    char id_str[PATROL_ID_STR_SIZE];
    get_id_str(id, id_str);
    LOG_DEBUG(">> set_cert_status: " CERT_FMT ", %d",
              host, proto, port, id_str, status);
#endif
    ASSERT_DB;

    PatrolRC ret = PATROL_get_cert_status(host, proto, port, id, NULL);
    if (ret != PATROL_OK)
        return ret;

    return write_val(host, proto, port, id, "status",
                     g_variant_new_uint32(status))
        ? PATROL_OK : PATROL_ERROR;
}

PatrolRC
PATROL_set_cert_active (const char *host, const char *proto, uint16_t port,
                        PatrolID id, PatrolPinMode pin_mode)
{
#if DEBUG
    char id_str[PATROL_ID_STR_SIZE];
    get_id_str(id, id_str);
    LOG_DEBUG(">> set_cert_active: " CERT_FMT ", %d",
              host, proto, port, id_str, pin_mode);
#endif
    ASSERT_DB;

    PatrolStatus status;
    PatrolRC ret = PATROL_get_cert_status(host, proto, port, id, &status);
    if (ret != PATROL_OK)
        return ret;

    DConfChangeset *ch = dconf_changeset_new();

    if (status != PATROL_STATUS_ACTIVE)
        set_val(ch, host, proto, port, id, "status",
                g_variant_new_uint32(PATROL_STATUS_ACTIVE));

    if (pin_mode == PATROL_PIN_EXCLUSIVE) {
        gint i, len = 0;
        gchar *peer_dir = g_strdup_printf(PEER_DIR, host, proto, port);
        gchar **keys = dconf_client_list(db, peer_dir, &len);

        for (i = 0; i < len; i++) {
            PatrolID cid;
            size_t key_len = strlen(keys[i]);
            if (key_len != PATROL_ID_STR_LEN + 1)
                continue;
            keys[i][PATROL_ID_STR_LEN] = '\0';
            if (PATROL_OK != set_id_str(cid, keys[i]))
                continue;

            if (PATROL_OK != PATROL_get_cert_status(host, proto, port, cid,
                                                    &status))
                continue;

            if (status != PATROL_STATUS_ACTIVE
                && 0 != PATROL_compare_ids(id, cid)) {

                set_val(ch, host, proto, port, id, "status",
                        g_variant_new_uint32(PATROL_STATUS_INACTIVE));
            }
        }
    }

    if (!dconf_client_change_fast(db, ch, NULL))
        ret = PATROL_ERROR;

    dconf_changeset_unref(ch);
    return ret;
}

int
PATROL_set_cert_seen (const char *host, const char *proto, uint16_t port,
                      PatrolID id)
{
#if DEBUG
    char id_str[PATROL_ID_STR_SIZE];
    get_id_str(id, id_str);
    LOG_DEBUG(">> set_cert_seen: " CERT_FMT, host, proto, port, id_str);
#endif
    if (!db)
        PATROL_init_db();
    ASSERT_DB;

    PatrolRC ret = PATROL_get_cert_status(host, proto, port, id, NULL);
    if (ret != PATROL_OK)
        return ret;

    GVariant *val = read_val_type(host, proto, port, id,
                                  "count_seen", G_VARIANT_TYPE_UINT64);
    uint64_t count = 0;
    if (val)
        count = g_variant_get_uint64(val);
    g_variant_unref(val);

    DConfChangeset *ch = dconf_changeset_new();

    set_val(ch, host, proto, port, id, "count_seen",
            g_variant_new_uint64(count + 1));

    set_val(ch, host, proto, port, id, "last_seen",
            g_variant_new_int64(time(NULL)));

    if (!dconf_client_change_fast(db, ch, NULL))
        ret = PATROL_ERROR;

    dconf_changeset_unref(ch);
    return ret;
}

PatrolRC
PATROL_set_pin_pubkey (const char *host, const char *proto,uint16_t port,
                       PatrolID id, const unsigned char *pin_pubkey,
                       size_t pin_pubkey_len, int64_t pin_expiry)
{
#if DEBUG
    char id_str[PATROL_ID_STR_SIZE];
    get_id_str(id, id_str);
    LOG_DEBUG(">> set_pin_pubkey: " CERT_FMT ", %zu, %" PRId64,
              host, proto, port, id_str,
              pin_pubkey_len, pin_expiry);
#endif
    ASSERT_DB;

    PatrolRC ret = PATROL_get_cert_status(host, proto, port, id, NULL);
    if (ret != PATROL_OK)
        return ret;

    DConfChangeset *ch = dconf_changeset_new();

    set_val(ch, host, proto, port, id, "pin_pubkey",
            g_variant_new_from_data(G_VARIANT_TYPE_BYTESTRING,
                                    pin_pubkey, pin_pubkey_len,
                                    TRUE, NULL, NULL));

    set_val(ch, host, proto, port, id, "pin_expiry",
            g_variant_new_int64(pin_expiry));


    if (!dconf_client_change_fast(db, ch, NULL))
        ret = PATROL_ERROR;

    dconf_changeset_unref(ch);
    return ret;
}
