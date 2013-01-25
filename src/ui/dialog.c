#include "config.h"
#include "common.h"

#include "dialog.h"
#include "dialog-window.h"
#include <certpatrol/patrol.h>

#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <gcr/gcr.h>

#include <locale.h>
#include <stdlib.h>
#include <string.h>

static gboolean
print_version_and_exit (const gchar *option_name, const gchar *value,
                        gpointer data, GError **error)
{
    g_print("%s %s\n", _("Certificate Patrol Dialog"), VERSION);
    exit(0);
}

static void
on_window_close (GtkWidget *widget, gpointer status)
{
    gtk_widget_hide(widget);
    gtk_main_quit();
    exit((intptr_t) status);
}

static void
on_cert_parsed (GcrParser *parser, gpointer arg)
{
    GcrCertificateChain *chain = *(GcrCertificateChain **) arg;
    GcrCertificate *cert;
    GcrCertificateWidget *widget;
    GckAttributes *attrs;

    attrs = gcr_parser_get_parsed_attributes(parser);
    widget = g_object_new(GCR_TYPE_CERTIFICATE_WIDGET,
                          "attributes", attrs, NULL);
    cert = gcr_certificate_widget_get_certificate(widget);

    if (chain)
        gcr_certificate_chain_add(chain, cert);

    LOG_DEBUG(">>> chain[%d] = %s\n",
              gcr_certificate_chain_get_length(chain) - 1,
              gcr_parser_get_parsed_label(parser));
}

GList *
load_certs (gchar *host, gchar *proto, guint16 port, gint64 cert_id)
{
    LOG_DEBUG(">> load_certs: %s, %s, %u, %ld\n",
              host, proto, port, cert_id);

    GtkWidget *dialog;
    PatrolRecord record, *records = NULL, *rec = NULL;
    size_t records_len = 0;
    GList *chain_list = NULL;
    GcrCertificateChain *chain = NULL;
    GcrParser *parser;
    size_t i;

    // retrieve new certificate for this peer
    if (PATROL_OK != PATROL_get_cert(host, strlen(host), proto, strlen(proto), 
                                     port, cert_id, &record)) {
        dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL,
                                        GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                        _("Error: can't find certificate #%lld"
                                          " for peer %s:%u (%s)"),
                                        (long long int) cert_id, host, port, proto);
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return NULL;
    }

    parser = gcr_parser_new();
    g_signal_connect(parser, "parsed", G_CALLBACK(on_cert_parsed), &chain);

    chain = gcr_certificate_chain_new();
    chain_list = g_list_prepend(chain_list, chain);

    for (i = 0; i < record.chain_len; i++) {
        if (!gcr_parser_parse_data(parser, record.chain[i].data,
                                   record.chain[i].size, NULL))
            goto load_certs_error;
    }

    // retrieve other active certificates for this peer, if any
    switch (PATROL_get_certs(host, strlen(host), proto, strlen(proto), port,
                             PATROL_STATUS_ACTIVE, false,
                             &records, &records_len)) {
    case PATROL_OK: // active certs found for peer
        LOG_DEBUG("certs found\n");
        rec = records;
        do {
            if (rec->id == cert_id)
              continue;

            LOG_DEBUG(">>> cert #%lld\n", (long long int) rec->id);
            chain = gcr_certificate_chain_new();
            chain_list = g_list_prepend(chain_list, chain);

            for (i = 0; i < record.chain_len; i++) {
                if (!gcr_parser_parse_data(parser, rec->chain[i].data,
                                           rec->chain[i].size, NULL))
                    goto load_certs_error;
            }
        } while ((rec = rec->next));
        break;

    case PATROL_DONE: // no active certs found for peer
        LOG_DEBUG("no certs found\n");
        break;

    default:
        goto load_certs_error;
    }

    return chain_list;

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

int
main (int argc, char *argv[])
{
    GOptionContext *context;
    GError *error = NULL;
    char **args;

    const GOptionEntry options[] = {
        { "version", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
          print_version_and_exit, N_("Show the application's version"), NULL },

        { G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_STRING_ARRAY,
          &args, NULL, N_("<hostname> <protocol> <port> <certID>") },

        { NULL },
    };

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
    g_option_context_add_main_entries(context, options, NULL);
    g_option_context_add_group(context, gtk_get_option_group(TRUE));

    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_critical("Failed to parse arguments: %s", error->message);
        g_error_free(error);
        g_option_context_free(context);
        return 1;
    }

    gchar *host = NULL, *proto = NULL;
    guint16 port = 0;
    gint64 cert_id = -1;

    if (args) {
        host = args[0];
        if (args[1]) {
            proto = args[1];
            if (args[2]) {
                port = atoi(args[2]);
                if (args[3]) {
                    cert_id = atoll(args[3]);
                }
            }
        }
    }

    if (cert_id < 0) {
        printf("%s", g_option_context_get_help(context, TRUE, NULL));
        exit(-1);
    }

    g_option_context_free(context);
    g_set_application_name(_("Certificate Patrol"));

    gtk_init(&argc, &argv);

    GList *chain_list = load_certs(host, proto, port, cert_id);
    if (!chain_list)
        exit(-1);

    PatrolDialogWindow *win = patrol_dialog_window_new(host, proto, port, chain_list);
    gtk_widget_show(GTK_WIDGET(win));

    g_signal_connect(win, "accept", G_CALLBACK(on_window_close), (void *) PATROL_CMD_ACCEPT);
    g_signal_connect(win, "accept-add", G_CALLBACK(on_window_close), (void *) PATROL_CMD_ACCEPT_ADD);
    g_signal_connect(win, "continue", G_CALLBACK(on_window_close), (void *) PATROL_CMD_CONTINUE);
    g_signal_connect(win, "reject", G_CALLBACK(on_window_close), (void *) PATROL_CMD_REJECT);
    g_signal_connect(win, "destroy", G_CALLBACK(on_window_close), (void *) PATROL_CMD_CONTINUE);

    gtk_main();

    return 0;
}
