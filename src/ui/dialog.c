#include "common.h"

#include "dialog.h"
#include "dialog-window.h"
#include "lib/patrol.h"

#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <gcr/gcr.h>

#include <locale.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

static PatrolID cert_id;
static gchar *cert_id_str = NULL;
static gchar *host = NULL, *proto = NULL, *app_name = NULL, **args = NULL;
static guint16 port = 0;
static gint chain_result = PATROL_ARG_UNKNOWN, chain_status = 0;
static gint dane_result = PATROL_ARG_UNKNOWN, dane_status = 0;
static PatrolCmdRC exit_status = PATROL_CMD_CONTINUE;
static gboolean new = false, change = false, reject = false, edit = false;
static PatrolPinMode pin_mode = PATROL_PIN_EXCLUSIVE;

static gboolean
print_version_and_exit (const gchar *option_name, const gchar *value,
                        gpointer data, GError **error)
{
    g_print("%s %s\n", _("Certificate Patrol Dialog"), VERSION);
    exit(0);
}

static void
on_window_close (GtkWidget *widget, GList *chains)
{
    gtk_widget_hide(widget);
    gtk_main_quit();
}

static void
on_window_response (GtkWidget *widget, PatrolCmdRC status, PatrolPinMode pmode,
                    GList *chains)
{
    exit_status = status;
    pin_mode = pmode;

    gtk_widget_hide(widget);
    gtk_main_quit();
}

static void
on_cert_parsed (GcrParser *parser, gpointer arg)
{
    PatrolDialogRecord *r = *(PatrolDialogRecord **) arg;
    GcrCertificate *cert;
    GcrCertificateWidget *widget;
    GckAttributes *attrs;

    attrs = gcr_parser_get_parsed_attributes(parser);
    widget = g_object_new(GCR_TYPE_CERTIFICATE_WIDGET,
                          "attributes", attrs, NULL);
    cert = gcr_certificate_widget_get_certificate(widget);

    if (r && r->chain) {
        gcr_certificate_chain_add(r->chain, cert);

        LOG_DEBUG(">>> chain[%d] = %s",
                  gcr_certificate_chain_get_length(r->chain) - 1,
                  gcr_parser_get_parsed_label(parser));
    }
}

PatrolRC
load_chain (GcrParser *parser, PatrolRecord *rec, PatrolDialogRecord **drec)
{
    LOG_DEBUG(">> load_chain");
    size_t i;
    PatrolDialogRecord *r = g_malloc(sizeof(PatrolDialogRecord));
    PATROL_set_id(r->id, rec->id);
    r->status = rec->status;
    r->der_chain = rec->chain;
    r->der_chain_len = rec->chain_len;
    r->first_seen = rec->first_seen;
    r->last_seen = rec->last_seen;
    r->count_seen = rec->count_seen;
    r->pin_expiry = rec->pin_expiry;
    r->pin_changed = false;
    r->pin_level = PATROL_get_pin_level(rec->chain, rec->chain_len, rec->pin_pubkey);

    *drec = r;
    r->chain = gcr_certificate_chain_new();
    for (i = 0; i < rec->chain_len; i++) {
        if (!gcr_parser_parse_data(parser, rec->chain[i].data,
                                   rec->chain[i].size, NULL)) {
            g_object_unref(r->chain);
            g_free(r);
            *drec = NULL;
            return PATROL_ERROR;
        }
    }

    return PATROL_OK;
}

GList *
load_chains (gchar *host, gchar *proto, guint16 port, PatrolID id)
{
    LOG_DEBUG(">> load_chains: %s, %s, %u", host, proto, port);

    GtkWidget *dialog;
    PatrolRecord record, *records = NULL, *rec = NULL;
    size_t records_len = 0;
    GList *chains = NULL;
    PatrolDialogRecord *drec = NULL;
    GcrParser *parser;
    char id_str[PATROL_ID_STR_LEN];

    // retrieve new certificate for this peer
    if (PATROL_OK != PATROL_get_cert(host, proto, port, id, PATROL_STATUS_ANY,
                                     &record)) {
        PATROL_get_id_str(id, id_str);
        dialog
            = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL,
                                     GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                     _("Error: can't find certificate ID %s\n"
                                       "for peer %s:%u (%s)"),
                                     id_str, host, port, proto);
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return NULL;
    }

    parser = gcr_parser_new();
    g_signal_connect(parser, "parsed", G_CALLBACK(on_cert_parsed), &drec);

    if (PATROL_OK != load_chain(parser, &record, &drec))
        goto load_certs_error;
    chains = g_list_prepend(chains, drec);

    // retrieve other active certificates for this peer, if any
    switch (PATROL_get_certs(host, proto, port,
                             PATROL_STATUS_ACTIVE,
                             false, &records, &records_len)) {
    case PATROL_OK: // active certs found for peer
        LOG_DEBUG(">>> certs found");
        for (rec = records; rec; rec = rec->next) {
            if (0 == PATROL_compare_ids(rec->id, cert_id))
                continue;

            if (PATROL_OK != load_chain(parser, rec, &drec))
                goto load_certs_error;
            chains = g_list_prepend(chains, drec);
        }
        break;

    case PATROL_DONE: // no active certs found for peer
        LOG_DEBUG(">>> no certs found");
        break;

    default:
        goto load_certs_error;
    }

    return g_list_reverse(chains);

load_certs_error:
    dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL,
                                    GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                    _("Error while loading certificates "
                                      "for peer %s:%u (%s)"),
                                    host, port, proto);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    return NULL;
}

static void
store_changed_pins (GList *chains)
{
    PatrolDialogRecord *rec;
    GList *item = chains;
    guint i;
    for (i = 0; item && item->data; item = item->next, i++) {
        rec = item->data;
        if (rec->pin_changed)
            PATROL_set_pin_from_chain(host, proto, port,
                                      rec->id, rec->pin_level,
                                      rec->der_chain, rec->der_chain_len);
    }
}

const GOptionEntry options[] = {
    { "version", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
      print_version_and_exit, N_("Show the application's version"), NULL },

    { "new", 'n', 0, G_OPTION_ARG_NONE, &new,
      N_("New certificate"), NULL },

    { "change", 'x', 0, G_OPTION_ARG_NONE, &change,
      N_("Changed certificate"), NULL },

    { "reject", 'x', 0, G_OPTION_ARG_NONE, &reject,
      N_("Rejected certificate"), NULL },

    { "edit", 'e', 0, G_OPTION_ARG_NONE, &edit,
      N_("Edit certificate"), NULL },

    { "host", 'H', 0, G_OPTION_ARG_STRING, &host,
      N_("Hostname of peer"), NULL },

    { "proto", 'p', 0, G_OPTION_ARG_STRING, &proto,
      N_("Protocol name of peer"), NULL },

    { "port", 'P', 0, G_OPTION_ARG_INT, &port,
      N_("Port number of peer"), NULL },

    { "id", 'i', 0, G_OPTION_ARG_STRING, &cert_id_str,
      N_("ID of new certificate"), NULL },

    { "chain-result", 'c', 0, G_OPTION_ARG_INT, &chain_result,
      N_("Chain validation result"), NULL },

    { "chain-status", 'C', 0, G_OPTION_ARG_INT, &chain_status,
      N_("Chain validation status"), NULL },

    { "dane-result", 'd', 0, G_OPTION_ARG_INT, &dane_result,
      N_("DANE validation result"), NULL },

    { "dane-status", 'D', 0, G_OPTION_ARG_INT, &dane_status,
      N_("DANE validation status"), NULL },

    { "app-name", 'a', 0, G_OPTION_ARG_STRING, &app_name,
      N_("Application name - defaults to parent process cmdline"), NULL },

    { G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_STRING_ARRAY, &args,
      NULL, NULL },

    { NULL },
};

int
main (int argc, char *argv[])
{
    GOptionContext *context;
    GError *error = NULL;

#if !GLIB_CHECK_VERSION(2,35,0)
    g_type_init();
#endif

#ifdef HAVE_LOCALE_H
    setlocale(LC_ALL, "");
#endif

#ifdef HAVE_GETTEXT
    bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
    textdomain(GETTEXT_PACKAGE);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
#endif

    context = g_option_context_new("");
    g_option_context_set_translation_domain(context, GETTEXT_PACKAGE);
    g_option_context_set_ignore_unknown_options(context, true);
    g_option_context_add_main_entries(context, options, NULL);
    g_option_context_add_group(context, gtk_get_option_group(TRUE));

    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_critical("Failed to parse arguments: %s", error->message);
        g_error_free(error);
        g_option_context_free(context);
        return 1;
    }

    if (!cert_id_str) {
        printf("%s", g_option_context_get_help(context, TRUE, NULL));
        exit(-1);
    }

    PATROL_init();
    PATROL_set_id_str(cert_id, cert_id_str);

    if (!app_name) {
        size_t i, len = 0;
        for (i = 0; args && args[i]; i++)
            len += strlen(args[i]) + 1;

        if (len) {
            app_name = malloc(len);
            size_t cur = 0;
            for (i = 0; args && args[i]; i++) {
                strncpy(app_name + cur, args[i], len - cur);
                cur += strlen(args[i]);
                if (cur < len - 1)
                    app_name[cur++] = ' ';
            }
        }
    }

    if (!app_name) {
        char *cmd = malloc(64);
        snprintf(cmd, 64, "ps -o args= -p %lu", (unsigned long) getppid());
        FILE *pipe = popen(cmd, "r");
        if (pipe) {
            app_name = malloc(4096);
            fgets(app_name, 4096, pipe);
            pclose(pipe);
        }
        if (!app_name) {
            app_name = malloc(32);
            snprintf(app_name, 32, "PID %lu", (unsigned long) getppid());
        }
    }

    LOG_DEBUG("app_name = [%s]", app_name);

    g_option_context_free(context);
    g_set_application_name(_("Certificate Patrol"));

    gtk_init(&argc, &argv);

    GList *chains = load_chains(host, proto, port, cert_id);
    if (!chains)
        exit(-1);

    PatrolEvent event
        = new ? PATROL_EVENT_NEW
        : change ? PATROL_EVENT_CHANGE
        : reject ? PATROL_EVENT_REJECT
        : PATROL_EVENT_NONE;

    PatrolDialogWindow *win
        = patrol_dialog_window_new(host, proto, port, chains, chain_result,
                                   dane_result, dane_status, app_name, event);
    gtk_widget_show(GTK_WIDGET(win));

    g_signal_connect(win, "response", G_CALLBACK(on_window_response), chains);
    g_signal_connect(win, "destroy", G_CALLBACK(on_window_close), chains);

    gtk_main();

    store_changed_pins(chains);

    switch (exit_status) {
    case PATROL_CMD_ACCEPT:
        PATROL_set_cert_active(host, proto, port, cert_id, pin_mode);
    case PATROL_CMD_CONTINUE:
        break;
    case PATROL_CMD_REJECT:
        PATROL_set_cert_status(host, proto, port, cert_id,
                               PATROL_STATUS_REJECTED);
    }

    PATROL_deinit();
    return exit_status;
}
