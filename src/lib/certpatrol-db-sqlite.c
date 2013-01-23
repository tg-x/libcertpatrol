#include "common.h"
#include "certpatrol.h"

#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <sqlite3.h>

static sqlite3 *db;

PatrolRC
PATROL_db_open()
{
    if (db)
        return PATROL_DONE; // already open

    static char *path = NULL;
    if (!path) {
        const char *home = getenv("HOME");
        char *dir =  malloc(strlen(home) + sizeof("/.certpatrol") + 1);
        sprintf(dir, "%s/.certpatrol", home);
        mkdir(dir, 700);

        path = malloc(strlen(dir) + sizeof("/certpatrol.sqlite") + 1);
        sprintf(path, "%s/certpatrol.sqlite", dir);
        free(dir);
    }

    LOG_DEBUG(">>> db_open: %s\n", path);

    sqlite3_enable_shared_cache(1);
    int ret = sqlite3_open(path, &db);

    if (ret != SQLITE_OK) {
      LOG_ERROR("Can't open database: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      return PATROL_ERROR;
    }

    ret = sqlite3_exec(db,
                       "PRAGMA read_uncommitted = true;"
                       "PRAGMA foreign_keys = ON;"

                       "CREATE TABLE IF NOT EXISTS status ("
                       "  value INTEGER PRIMARY KEY, description"
                       ");"

                       "CREATE TABLE IF NOT EXISTS certs ("
                       "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                       "  cert BLOB UNIQUE, ca_chain BLOB, pin_pubkey BLOB, pin_expiry INTEGER"
                       ");"

                       "CREATE TABLE IF NOT EXISTS peers ("
                       "  host VARCHAR, proto VARCHAR, port INTEGER,"
                       "  status INTEGER DEFAULT 0 REFERENCES status(value),"
                       "  cert_id REFERENCES certs(id),"
                       "  first_seen INTEGER DEFAULT (strftime('%s', 'now')),"
                       "  last_seen  INTEGER DEFAULT (strftime('%s', 'now')),"
                       "  count_seen INTEGER DEFAULT 1,"
                       "  PRIMARY KEY (host, proto, port, cert_id)"
                       ");",
                       NULL, NULL, NULL);
    if (ret != SQLITE_OK) {
	LOG_ERROR("Error creating tables: %s (#%d)\n", sqlite3_errmsg(db), ret);
    }

    ret = sqlite3_exec(db,
                       "INSERT OR IGNORE INTO status VALUES(-1, 'rejected');"
                       "INSERT OR IGNORE INTO status VALUES( 0, 'inactive');"
                       "INSERT OR IGNORE INTO status VALUES( 1, 'active');",
                       NULL, NULL, NULL);
    if (ret != SQLITE_OK) {
	LOG_ERROR("Error inserting values: %s (#%d)\n", sqlite3_errmsg(db), ret);
    }

    return PATROL_OK;
}

PatrolRC
PATROL_db_close()
{
    if (sqlite3_close(db) == SQLITE_OK) {
        db = NULL;
        return PATROL_OK;
    }
    return PATROL_ERROR;
}

PatrolRC
PATROL_get_certs (const char *host, size_t host_len,
                      const char *proto, size_t proto_len, uint16_t port,
                      PatrolStatus status, bool wildcard,
                      PatrolRecord **records, size_t *records_len)
{
    if (!db) {
        PATROL_db_open();
        if (!db)
            return PATROL_ERROR;
    }

    static sqlite3_stmt *stmt_exact = NULL, *stmt_wild = NULL;
    if (!stmt_exact) {
        sqlite3_prepare_v2(
            db,
            C2ARG("SELECT cert_id, status, first_seen, last_seen, count_seen, "
                  "       cert, ca_chain, pin_pubkey, pin_expiry "
                  "FROM peers "
                  "INNER JOIN certs ON cert_id = id "
                  "WHERE status = ? AND port = ? AND proto = ? AND host = ? "
                  "ORDER BY cert_id"),
            &stmt_exact, NULL);
    }
    if (!stmt_wild) {
        sqlite3_prepare_v2(
            db,
            C2ARG("SELECT cert_id, status, first_seen, last_seen, count_seen, "
                  "       cert, ca_chain, pin_pubkey, pin_expiry "
                  "FROM peers "
                  "INNER JOIN certs ON cert_id = id "
                  "WHERE status = ? AND port = ? AND proto = ? AND (host = ? OR host = '*' || ?) "
                  "ORDER BY rowid"),
            &stmt_wild, NULL);
    }

    int ret = PATROL_ERROR;
    sqlite3_stmt *stmt = stmt_exact;
    const char *host_wild = NULL;
    if (wildcard) {
        host_wild = memchr(host, '.', host_len);
        if (host_wild)
            stmt = stmt_wild;
    }

    if (sqlite3_bind_int(stmt, 1, status) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 2, port) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 3, proto, proto_len, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 4, host, host_len, SQLITE_STATIC) != SQLITE_OK ||
        (host_wild &&
         sqlite3_bind_text(stmt, 5, host_wild, host_len - (host_wild - host),
                           SQLITE_STATIC) != SQLITE_OK)) {

	LOG_ERROR("find_certs: bind: %s (#%d)\n",
                  sqlite3_errmsg(db), sqlite3_errcode(db));
    } else {
        PatrolRecord *rec = NULL;
        int r;
        *records = NULL;
        *records_len = 0;
        do {
            r = sqlite3_step(stmt);
            switch (r) {
            case SQLITE_ROW:
                LOG_DEBUG(">>> row\n");
                if (!rec) {
                    rec = *records = malloc(sizeof(PatrolRecord));
                } else {
                    rec = rec->next = malloc(sizeof(PatrolRecord));
                }

                rec->id = sqlite3_column_int64(stmt, 0);
                rec->status = sqlite3_column_int(stmt, 1);
                rec->first_seen = sqlite3_column_int64(stmt, 2);
                rec->last_seen = sqlite3_column_int64(stmt, 3);
                rec->count_seen = sqlite3_column_int64(stmt, 4);

                rec->cert.size = sqlite3_column_bytes(stmt, 5);
                rec->cert.data = malloc(rec->cert.size);
                memcpy(rec->cert.data, sqlite3_column_blob(stmt, 5), rec->cert.size);

                rec->ca_chain.size = sqlite3_column_bytes(stmt, 6);
                rec->ca_chain.data = malloc(rec->ca_chain.size);
                memcpy(rec->ca_chain.data, sqlite3_column_blob(stmt, 6), rec->ca_chain.size);

                rec->pin_pubkey.size = sqlite3_column_bytes(stmt, 7);
                rec->pin_pubkey.data = malloc(rec->pin_pubkey.size);
                memcpy(rec->pin_pubkey.data, sqlite3_column_blob(stmt, 7), rec->pin_pubkey.size);

                rec->pin_expiry = sqlite3_column_int64(stmt, 8);
                rec->next = NULL;

                (*records_len)++;
                break;
            case SQLITE_DONE:
                LOG_DEBUG(">>> done\n");
                ret = *records_len ? PATROL_OK : PATROL_DONE;
                break;
            default:
                LOG_ERROR("find_certs: step: %s (#%d/%d)\n", sqlite3_errmsg(db),
                          sqlite3_errcode(db), sqlite3_extended_errcode(db));
            }
        } while (r == SQLITE_ROW);
    }

    sqlite3_reset(stmt);
    return ret;
}

PatrolRC
PATROL_add_cert (const char *host, size_t host_len,
                     const char *proto, size_t proto_len,
                     uint16_t port, PatrolStatus status,
                     const PatrolData *chain, size_t chain_len,
                     const unsigned char *pin_pubkey, size_t pin_pubkey_len,
                     int64_t pin_expiry, int64_t *cert_id)
{
    if (!db) {
        PATROL_db_open();
        if (!db)
            return PATROL_ERROR;
    }
    if (!chain_len)
        return PATROL_ERROR;

    static sqlite3_stmt *stmt_sel_cert = NULL, *stmt_begin = NULL, *stmt_ins_cert = NULL,
                        *stmt_ins_peer = NULL, *stmt_commit = NULL, *stmt_rollback = NULL;
    if (!stmt_sel_cert)
        sqlite3_prepare_v2(
            db,
            C2ARG("SELECT id FROM certs WHERE cert = ?"),
            &stmt_sel_cert, NULL);
    if (!stmt_begin)
        sqlite3_prepare_v2(db, C2ARG("BEGIN"), &stmt_begin, NULL);
    if (!stmt_ins_cert)
        sqlite3_prepare_v2(
            db,
            C2ARG("INSERT INTO certs (cert, ca_chain, pin_pubkey, pin_expiry) "
                  "VALUES (?, ?, ?, ?)"),
            &stmt_ins_cert, NULL);
    if (!stmt_ins_peer)
        sqlite3_prepare_v2(
            db,
            C2ARG("INSERT INTO peers (host, proto, port, status, cert_id) "
                  "VALUES (?, ?, ?, ?, last_insert_rowid())"),
            &stmt_ins_peer, NULL);
    if (!stmt_commit)
        sqlite3_prepare_v2(db, C2ARG("COMMIT"), &stmt_commit, NULL);
    if (!stmt_rollback)
        sqlite3_prepare_v2(db, C2ARG("ROLLBACK"), &stmt_rollback, NULL);

    PatrolRC ret = PATROL_ERROR;
    char *ca_chain = NULL;
    size_t i, ca_chain_len = 0;
    *cert_id = -1;

    if (sqlite3_bind_blob(stmt_sel_cert, 1, chain[0].data, chain[0].size,
                          SQLITE_STATIC) != SQLITE_OK) {
        LOG_ERROR("add_cert: sel bind: %s (#%d)\n",
                  sqlite3_errmsg(db), sqlite3_errcode(db));
    } else {
        switch (sqlite3_step(stmt_sel_cert)) {
        case SQLITE_ROW:
            *cert_id = sqlite3_column_int64(stmt_sel_cert, 0);
            ret = PATROL_OK;
            break;
        case SQLITE_DONE:
            ret = PATROL_OK;
            break;
        case SQLITE_BUSY:
        default:
            LOG_ERROR("add_cert: sel step: %s (#%d/%d)\n", sqlite3_errmsg(db),
                      sqlite3_errcode(db), sqlite3_extended_errcode(db));
        }
    }

    sqlite3_reset(stmt_sel_cert);
    if (ret == PATROL_ERROR)
        return ret;

    ret = PATROL_ERROR;

    switch (sqlite3_step(stmt_begin)) {
    case SQLITE_DONE:
        break;
    case SQLITE_BUSY:
    default:
        LOG_ERROR("add_cert: begin step: %s (#%d/%d)\n", sqlite3_errmsg(db),
                  sqlite3_errcode(db), sqlite3_extended_errcode(db));
        goto add_cert_end;
    }

    if (*cert_id < 0) {
        // construct a DER-encoded buffer of CA certificates

        for (i = 1; i < chain_len; i++)
            ca_chain_len += chain[i].size;

        ca_chain = malloc(ca_chain_len);

        for (i = 1; i < chain_len; i++)
            memcpy(ca_chain, chain[i].data, chain[i].size);

        if (sqlite3_bind_blob(stmt_ins_cert, 1, chain[0].data, chain[0].size, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_blob(stmt_ins_cert, 2, ca_chain, ca_chain_len, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_blob(stmt_ins_cert, 3, pin_pubkey, pin_pubkey_len, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_int64(stmt_ins_cert, 4, pin_expiry) != SQLITE_OK) {

            LOG_ERROR("add_cert: ins cert bind: %s (#%d)\n", sqlite3_errmsg(db), sqlite3_errcode(db));
            goto add_cert_end;
        }

        switch (sqlite3_step(stmt_ins_cert)) {
        case SQLITE_DONE:
            if (cert_id)
                *cert_id = sqlite3_last_insert_rowid(db);
            LOG_DEBUG(">>> cert_id = %" PRId64 "\n", *cert_id);
            break;
        case SQLITE_BUSY:
            // TODO retry
        default:
            LOG_ERROR("add_cert: cert step: %s (#%d/%d)\n", sqlite3_errmsg(db),
                      sqlite3_errcode(db), sqlite3_extended_errcode(db));
            goto add_cert_end;
        }
    }

    if (sqlite3_bind_text(stmt_ins_peer, 1, host, host_len, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt_ins_peer, 2, proto, proto_len, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(stmt_ins_peer, 3, port) != SQLITE_OK ||
        sqlite3_bind_int(stmt_ins_peer, 4, status) != SQLITE_OK) {

        LOG_ERROR("add_cert: ins bind: %s (#%d)\n", sqlite3_errmsg(db), sqlite3_errcode(db));
        goto add_cert_end;
    }

    switch (sqlite3_step(stmt_ins_peer)) {
    case SQLITE_DONE:
        break;
    case SQLITE_CONSTRAINT:
        if (*cert_id >= 0)
            ret = PATROL_DONE;
        sqlite3_step(stmt_rollback);
        sqlite3_reset(stmt_rollback);
        goto add_cert_end;
    case SQLITE_BUSY:
        // TODO retry
    default:
        LOG_ERROR("add_cert: peer step: %s (#%d/%d)\n", sqlite3_errmsg(db),
                  sqlite3_errcode(db), sqlite3_extended_errcode(db));
        goto add_cert_end;
    }

    switch (sqlite3_step(stmt_commit)) {
    case SQLITE_DONE:
        ret = PATROL_OK;
        break;
    case SQLITE_BUSY:
    default:
        LOG_ERROR("add_cert: commit step: %s (#%d/%d)\n", sqlite3_errmsg(db),
                  sqlite3_errcode(db), sqlite3_extended_errcode(db));
        goto add_cert_end;
    }

add_cert_end:
    sqlite3_reset(stmt_begin);
    sqlite3_reset(stmt_ins_cert);
    sqlite3_reset(stmt_ins_peer);
    sqlite3_reset(stmt_commit);

    if (ca_chain)
        free(ca_chain);

    return ret;
}

PatrolRC
PATROL_set_cert_status (const char *host, size_t host_len,
                            const char *proto, size_t proto_len,
                            uint16_t port, int64_t cert_id, int status)
{
    if (!db) {
        PATROL_db_open();
        if (!db)
            return PATROL_ERROR;
    }

    static sqlite3_stmt *stmt = NULL;
    if (!stmt) {
        sqlite3_prepare_v2(
            db,
            C2ARG("UPDATE peers "
                  "SET status = ? "
                  "WHERE cert_id = ? AND host = ? AND proto = ? AND port = ?"),
            &stmt, NULL);
    }

    PatrolRC ret = PATROL_ERROR;

    if (sqlite3_bind_int(stmt, 1, cert_id) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 2, status) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 3, host, host_len, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 4, proto, proto_len, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 5, port) != SQLITE_OK) {

	LOG_ERROR("set_cert_status bind: %s (#%d)\n", sqlite3_errmsg(db), sqlite3_errcode(db));
    } else {
	switch (sqlite3_step(stmt)) {
	case SQLITE_DONE:
            ret = sqlite3_total_changes(db);
	    break;
        case SQLITE_BUSY:
            // TODO retry
	default:
	    LOG_ERROR("set_cert_status_step: %s (#%d)\n",
		      sqlite3_errmsg(db), sqlite3_errcode(db));
	}
    }

    sqlite3_reset(stmt);
    return ret;
}

PatrolRC
PATROL_set_cert_active (const char *host, size_t host_len,
                            const char *proto, size_t proto_len,
                            uint16_t port, int64_t cert_id,
                            PatrolPinMode pin_mode)
{
    if (!db) {
        PATROL_db_open();
        if (!db)
            return PATROL_ERROR;
    }

    static sqlite3_stmt *stmt_multi = NULL, *stmt_excl = NULL;
    if (!stmt_multi) {
        sqlite3_prepare_v2(
            db,
            C2ARG("UPDATE peers "
                  "SET status = 1 "
                  "WHERE cert_id = ? AND host = ? AND proto = ? AND port = ?"),
            &stmt_multi, NULL);
    }
    if (!stmt_excl) {
        sqlite3_prepare_v2(
            db,
            C2ARG("UPDATE peers "
                  "SET status = (cert_id = ?) "
                  "WHERE host = ? AND proto = ? AND port = ?"),
            &stmt_excl, NULL);
    }

    sqlite3_stmt *stmt = pin_mode == PATROL_PIN_EXCLUSIVE ? stmt_excl : stmt_multi;
    PatrolRC ret = PATROL_ERROR;

    if (sqlite3_bind_int64(stmt, 1, cert_id) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, host, host_len, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 3, proto, proto_len, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 4, port) != SQLITE_OK) {

	LOG_ERROR("activate_cert: bind: %s (#%d)\n", sqlite3_errmsg(db), sqlite3_errcode(db));
    } else {
	switch (sqlite3_step(stmt)) {
	case SQLITE_DONE:
            ret = sqlite3_total_changes(db);
	    break;
        case SQLITE_BUSY:
            // TODO retry
	default:
	    LOG_ERROR("activate_cert: step: %s (#%d)\n",
		      sqlite3_errmsg(db), sqlite3_errcode(db));
	}
    }

    sqlite3_reset(stmt);
    return ret;
}

int
PATROL_set_cert_seen (const char *host, size_t host_len,
                          const char *proto, size_t proto_len,
                          uint16_t port, int64_t cert_id)
{
    if (!db)
        PATROL_db_open();
    if (!db)
        return PATROL_ERROR;

    static sqlite3_stmt *stmt = NULL;
    if (!stmt) {
        sqlite3_prepare_v2(
            db,
            C2ARG("UPDATE peers "
                  "SET last_seen = strftime('%s', 'now'),"
                  "    count_seen = count_seen + 1 "
                  "WHERE cert_id = ? AND host = ? AND proto = ? AND port = ?"),
            &stmt, NULL);
    }

    PatrolRC ret = PATROL_ERROR;

    if (sqlite3_bind_int64(stmt, 1, cert_id) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, host, host_len, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 3, proto, proto_len, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 4, port) != SQLITE_OK) {

	LOG_ERROR("set_cert_seen: bind: %s (#%d)\n", sqlite3_errmsg(db), sqlite3_errcode(db));
    } else {
	switch (sqlite3_step(stmt)) {
	case SQLITE_DONE:
            ret = sqlite3_total_changes(db);
	    break;
        case SQLITE_BUSY:
            // TODO retry
	default:
	    LOG_ERROR("set_cert_seen: step: %s (#%d)\n",
		      sqlite3_errmsg(db), sqlite3_errcode(db));
	}
    }

    sqlite3_reset(stmt);
    return ret;
}

PatrolRC
PATROL_set_pin (const char *host, size_t host_len,
                    const char *proto, size_t proto_len,
                    uint16_t port, int64_t cert_id,
                    const unsigned char *pin_pubkey, size_t pin_pubkey_len,
                    int64_t pin_expiry)
{
    if (!db) {
        PATROL_db_open();
        if (!db)
            return PATROL_ERROR;
    }

    static sqlite3_stmt *stmt = NULL;
    if (!stmt) {
        sqlite3_prepare_v2(
            db,
            C2ARG("UPDATE certs "
                  "SET pin_pubkey = ?, pin_expiry = ? "
                  "WHERE id = ? "
                  "  AND 1 <= (SELECT count(*) FROM peers "
                  "            WHERE cert_id = ? AND host = ? "
                  "                AND proto = ? AND port = ?)"),
            &stmt, NULL);
    }

    int ret = PATROL_ERROR;

    if (sqlite3_bind_blob(stmt, 1, pin_pubkey, pin_pubkey_len, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 2, pin_expiry) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 3, cert_id) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 4, cert_id) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 5, host, host_len, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 6, proto, proto_len, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 7, port) != SQLITE_OK) {

	LOG_ERROR("set_pin_pubkey: bind: %s (#%d)\n", sqlite3_errmsg(db), sqlite3_errcode(db));
    } else {
	switch (sqlite3_step(stmt)) {
	case SQLITE_DONE:
            ret = sqlite3_changes(db);
	    break;
        case SQLITE_BUSY:
            // TODO retry
	default:
	    LOG_ERROR("set_pin_pubkey: step: %s (#%d)\n",
		      sqlite3_errmsg(db), sqlite3_errcode(db));
	}
    }

    sqlite3_reset(stmt);
    return ret;
}
