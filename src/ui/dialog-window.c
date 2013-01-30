#include "common.h"
#include "dialog.h"
#include "dialog-window.h"

#include <glib/gi18n-lib.h>
#include <gtk/gtk.h>
#include <gcr/gcr.h>

#ifdef HAVE_GNUTLS_DANE
# include <gnutls/gnutls.h>
# include <gnutls/dane.h>
#endif

#include <locale.h>
#include <string.h>
#include <time.h>

struct _PatrolDialogWindowPrivate {
    const gchar *host;
    const gchar *proto;
    gint16 port;
    GList *chains;

    gboolean add;

    GtkWidget *msg;
    GtkWidget *icon;
    GtkWidget *chain_msg;
    GtkWidget *chain_icon;
#ifdef HAVE_GNUTLS_DANE
    GtkWidget *dane_msg;
    GtkWidget *dane_icon;
#endif
    GtkWidget *new_chain;
    GtkWidget *old_chains;

    GcrViewer *viewer;
    GcrCertificateRenderer *renderer;
};

enum {
    SIGNAL_ACCEPT,
    SIGNAL_ACCEPT_ADD,
    SIGNAL_CONTINUE,
    SIGNAL_REJECT,
    SIGNALS_NUM,
};

enum {
    COL_NAME,
    COL_PIN,
    COL_CERT,
    COLS_NUM,
};

static GtkTreeSelection *cur_sel = NULL;

static guint signals[SIGNALS_NUM];

G_DEFINE_TYPE(PatrolDialogWindow, patrol_dialog_window, GTK_TYPE_WINDOW);

static void
on_add_toggled (GtkButton *button, gpointer arg)
{
    PatrolDialogWindow *self = PATROL_DIALOG_WINDOW(arg);
    self->pv->add = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button));
}

static void
on_accept_clicked (GtkButton *button, gpointer arg)
{
    PatrolDialogWindow *self = PATROL_DIALOG_WINDOW(arg);

    int sig = self->pv->add ? SIGNAL_ACCEPT_ADD : SIGNAL_ACCEPT;
    g_signal_emit(self, signals[sig], 0);

    gtk_widget_destroy(GTK_WIDGET(self));
}

static void
on_continue_clicked (GtkButton *button, gpointer arg)
{
    PatrolDialogWindow *self = PATROL_DIALOG_WINDOW(arg);

    g_signal_emit(self, signals[SIGNAL_CONTINUE], 0);

    gtk_widget_destroy(GTK_WIDGET(self));
}

static void
on_reject_clicked (GtkButton *button, gpointer arg)
{
    PatrolDialogWindow *self = PATROL_DIALOG_WINDOW(arg);

    g_signal_emit(self, signals[SIGNAL_REJECT], 0);

    gtk_widget_destroy(GTK_WIDGET(self));
}

static void
patrol_dialog_window_constructed (GObject *obj)
{
    G_OBJECT_CLASS(patrol_dialog_window_parent_class)->constructed(obj);

    PatrolDialogWindow *self = PATROL_DIALOG_WINDOW(obj);
    PatrolDialogWindowPrivate *pv = self->pv;

    gtk_window_set_title(GTK_WINDOW(self), _("Certificate Patrol"));
    gtk_window_set_default_size(GTK_WINDOW(self), 500, 700);
    //gtk_window_set_position(GTK_WINDOW(self), GTK_WIN_POS_MOUSE);

    /* content area */
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_left(GTK_WIDGET(content), 10);
    gtk_widget_set_margin_right(GTK_WIDGET(content), 10);
    gtk_container_add(GTK_CONTAINER(self), content);

    /* messages */
    GtkWidget *msgbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(content), msgbox, FALSE, FALSE, 6);

    pv->icon = gtk_image_new();
    gtk_box_pack_start(GTK_BOX(msgbox), pv->icon, FALSE, FALSE, 6);

    pv->msg = gtk_label_new(NULL);
    gtk_widget_set_halign(GTK_WIDGET(pv->msg), GTK_ALIGN_START);
    gtk_widget_set_margin_top(GTK_WIDGET(pv->msg), 25);
    gtk_box_pack_start(GTK_BOX(msgbox), pv->msg, FALSE, FALSE, 6);

    msgbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(content), msgbox, FALSE, FALSE, 6);

    pv->chain_icon = gtk_image_new();
    gtk_box_pack_start(GTK_BOX(msgbox), pv->chain_icon, FALSE, FALSE, 6);

    pv->chain_msg = gtk_label_new(NULL);
    gtk_widget_set_halign(GTK_WIDGET(pv->chain_msg), GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(msgbox), pv->chain_msg, FALSE, FALSE, 6);

#ifdef HAVE_GNUTLS_DANE
    msgbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(content), msgbox, FALSE, FALSE, 6);

    pv->dane_icon = gtk_image_new();
    gtk_box_pack_start(GTK_BOX(msgbox), pv->dane_icon, FALSE, FALSE, 6);

    pv->dane_msg = gtk_label_new(NULL);
    gtk_widget_set_halign(GTK_WIDGET(pv->dane_msg), GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(msgbox), pv->dane_msg, FALSE, FALSE, 6);
#endif

    /* details: chains & cert viewer */
    GtkWidget *details = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(content), details, TRUE, TRUE, 6);

    GtkWidget *chains = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_box_pack_start(GTK_BOX(details), chains, FALSE, FALSE, 0);

    GtkWidget *viewport = gtk_viewport_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(chains), viewport, FALSE, FALSE, 0);
    pv->new_chain = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_margin_left(pv->new_chain, 5);
    gtk_widget_set_margin_top(pv->new_chain, 5);
    gtk_widget_set_margin_bottom(pv->new_chain, 5);
    //gtk_box_pack_start(GTK_BOX(chains), pv->new_chain, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(viewport), pv->new_chain);

    GtkWidget *frame = gtk_frame_new(NULL);
    gtk_box_pack_start(GTK_BOX(chains), frame, TRUE, TRUE, 0);

    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
                GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(frame), scrolled_window);

    pv->old_chains = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_left(pv->old_chains, 5);
    gtk_widget_set_margin_top(pv->old_chains, 5);
    gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrolled_window),
                                                    GTK_WIDGET(pv->old_chains));
    //gtk_box_pack_start(GTK_BOX(chains), pv->old_chains, TRUE, TRUE, 0);
    
    gtk_box_pack_start(GTK_BOX(details), GTK_WIDGET(pv->viewer), TRUE, TRUE, 0);

    /* additional pin checkbox */
    GtkWidget *add = gtk_check_button_new_with_mnemonic(
        _("_Store additional pin instead of replacing existing ones"));
    g_signal_connect_object(GTK_TOGGLE_BUTTON(add), "toggled",
                            G_CALLBACK(on_add_toggled), self, 0);

    /* button box */
    GtkWidget *bbox = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_halign(GTK_WIDGET(bbox), GTK_ALIGN_END);
    gtk_widget_set_margin_right(GTK_WIDGET(bbox), 6);
    gtk_box_set_spacing(GTK_BOX(bbox), 12);
    gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_END);

    gtk_box_pack_end(GTK_BOX(content), bbox, FALSE, FALSE, 12);
    gtk_box_pack_end(GTK_BOX(content), add, FALSE, FALSE, 0);

    /* reject button */
    GtkWidget *btn = gtk_button_new_from_stock(GTK_STOCK_NO);
    gtk_button_set_label(GTK_BUTTON(btn), _("_Reject"));
    gtk_widget_set_tooltip_text(btn, _("Reject certificate.\nCauses verification failure."));
    gtk_box_pack_start(GTK_BOX(bbox), btn, FALSE, TRUE, 0);
    g_signal_connect_object (GTK_BUTTON(btn), "clicked",
                             G_CALLBACK(on_reject_clicked), self, 0);

    /* continue button */
    btn = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
    gtk_button_set_label(GTK_BUTTON(btn), _("_Continue"));
    gtk_widget_set_tooltip_text(btn, _("Temporarily accept public key, but do not pin it."));
    gtk_box_pack_start(GTK_BOX(bbox), btn, FALSE, TRUE, 0);
    g_signal_connect_object(GTK_BUTTON(btn), "clicked",
                            G_CALLBACK(on_continue_clicked), self, 0);
    gtk_widget_grab_focus(btn);

    /* accept button */
    btn = gtk_button_new_from_stock(GTK_STOCK_YES);
    gtk_button_set_label(GTK_BUTTON(btn), _("_Accept"));
    gtk_widget_set_tooltip_text(btn, _("Accept and pin public key.\nReplace or add pin depending on the above setting."));
    gtk_box_pack_start(GTK_BOX(bbox), btn, FALSE, TRUE, 0);
    g_signal_connect_object(GTK_BUTTON(btn), "clicked",
                            G_CALLBACK(on_accept_clicked), self, 0);

    gtk_widget_show_all(content);
}

static void
on_cert_changed (GcrCertificateRenderer *renderer, gpointer arg)
{
    GtkTreeView *tree_view = GTK_TREE_VIEW(arg);
    GtkTreeSelection *tree_sel = gtk_tree_view_get_selection(tree_view);
    if (tree_sel != cur_sel)
        gtk_tree_selection_unselect_all(tree_sel);
}

static void
on_tree_selection_changed (GtkTreeSelection *tree_sel, gpointer arg)
{
    PatrolDialogWindow *self = PATROL_DIALOG_WINDOW(arg);
    GcrCertificate *cert;
    GtkTreeIter iter;
    GtkTreeModel *tree_model;

    if (gtk_tree_selection_get_selected(tree_sel, &tree_model, &iter)) {
        gtk_tree_model_get(tree_model, &iter, COL_CERT, &cert, -1);
        cur_sel = tree_sel;
        gcr_certificate_renderer_set_certificate(self->pv->renderer, cert);
        cur_sel = NULL;
    }
}

static gboolean
on_tree_view_focus (GtkTreeView *tree_view, GtkDirectionType dir, gpointer arg)
{
    GtkTreeSelection *tree_sel = gtk_tree_view_get_selection(tree_view);

    on_tree_selection_changed(tree_sel, arg);

    return FALSE;
}

static void
on_radio_toggled (GtkCellRendererToggle *renderer, gchar *path_str, gpointer arg)
{
    GtkTreeModel *tree_model = GTK_TREE_MODEL(arg);
    GtkTreeIter iter, current, child;
    gboolean enabled, valid = TRUE;
    GtkTreePath *path = gtk_tree_path_new_from_string(path_str);
    gtk_tree_model_get_iter(tree_model, &iter, path);
    gtk_tree_model_get(tree_model, &iter, COL_PIN, &enabled, -1);

    if (!enabled) {
        /* set all other values to FALSE */
        gtk_tree_model_get_iter_first(tree_model, &current);
        while (valid) {
            gtk_tree_store_set(GTK_TREE_STORE(tree_model), &current, COL_PIN, FALSE, -1);
            valid = gtk_tree_model_iter_children(tree_model, &child, &current);
            current = child;
        }
        /* set radio button to TRUE */
        gtk_tree_store_set(GTK_TREE_STORE(tree_model), &iter, COL_PIN, TRUE, -1);
    }
}

static void
load_chain (PatrolDialogWindow *self, GcrCertificateChain *chain,
            guint idx, GtkWidget *container)
{
    /* build tree model */
    GtkTreeStore *tree_store = gtk_tree_store_new(COLS_NUM, G_TYPE_STRING,
                                                  G_TYPE_BOOLEAN, G_TYPE_POINTER);

    GtkTreeIter *parent = NULL, iter;
    gint i, num_certs = gcr_certificate_chain_get_length(chain);

    for (i = num_certs - 1; i >= 0; i--) {
        GcrCertificate *cert = gcr_certificate_chain_get_certificate(chain, i);
        gchar *label = gcr_certificate_get_subject_name(cert);

        gtk_tree_store_append(tree_store, &iter, parent);
        gtk_tree_store_set(tree_store, &iter,
                           COL_NAME, label,
                           COL_PIN, FALSE,
                           COL_CERT, cert,
                           -1);
        parent = &iter;
        g_free(label);
    }

    /* set hierarchy title */
    GtkWidget *title_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start(GTK_BOX(container), title_box, FALSE, FALSE, 0);
    gtk_widget_show(title_box);
    gchar *text;
    GtkWidget *title = gtk_label_new(NULL);
    if (idx == 0) {     /* new chain */
        text = g_strdup_printf(_("<b>New Certificate</b>"));
        gtk_label_set_markup(GTK_LABEL(title), text);
        gtk_widget_set_halign(GTK_WIDGET(title), GTK_ALIGN_START);
        gtk_box_pack_start(GTK_BOX(title_box), title, FALSE, FALSE, 0);
        gtk_widget_show(title);

        g_free(text);
    }
    else {
        GDateTime *timestamp = g_date_time_new_from_unix_local(time(NULL));
        gchar *stored_str = g_date_time_format(timestamp, "%Y-%m-%d %H:%M:%S");
        timestamp = g_date_time_new_from_unix_local(time(NULL));
        gchar *expires_str = g_date_time_format(timestamp, "%Y-%m-%d %H:%M:%S");
        int count = 9;

        text = g_strdup_printf(_("<b>Stored Certificate #%d</b>"), idx);
        gtk_label_set_markup(GTK_LABEL(title), text);
        gtk_widget_set_halign(GTK_WIDGET(title), GTK_ALIGN_START);
        gtk_widget_set_margin_bottom(GTK_WIDGET(title), 2);
        gtk_box_pack_start(GTK_BOX(title_box), title, FALSE, FALSE, 0);
        gtk_widget_show(title);

        text = g_strdup_printf(_("View count: %d"), count);
        title = gtk_label_new(NULL);
        gtk_label_set_markup(GTK_LABEL(title), text);
        gtk_widget_set_halign(GTK_WIDGET(title), GTK_ALIGN_START);
        gtk_widget_set_margin_left(GTK_WIDGET(title), 5);
        gtk_box_pack_start(GTK_BOX(title_box), title, FALSE, FALSE, 0);
        gtk_widget_show(title);

        text = g_strdup_printf(_("Stored since: %s"), stored_str);
        title = gtk_label_new(NULL);
        gtk_label_set_markup(GTK_LABEL(title), text);
        gtk_widget_set_halign(GTK_WIDGET(title), GTK_ALIGN_START);
        gtk_widget_set_margin_left(GTK_WIDGET(title), 5);
        gtk_box_pack_start(GTK_BOX(title_box), title, FALSE, FALSE, 0);
        gtk_widget_show(title);

        text = g_strdup_printf(_("Pin Expires: %s"), expires_str);
        title = gtk_label_new(NULL);
        gtk_label_set_markup(GTK_LABEL(title), text);
        gtk_widget_set_halign(GTK_WIDGET(title), GTK_ALIGN_START);
        gtk_widget_set_margin_left(GTK_WIDGET(title), 5);
        gtk_box_pack_start(GTK_BOX(title_box), title, FALSE, FALSE, 0);
        gtk_widget_show(title);

        g_free(text);
        g_free(stored_str);
        g_free(expires_str);
    }

    /* build tree viewer */
    GtkWidget *tree_view;
    tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(tree_store));
    gtk_tree_view_expand_all(GTK_TREE_VIEW(tree_view));
    //if (idx == 0) {
    //    GtkWidget *frame = gtk_frame_new(NULL);
    //    gtk_box_pack_start(GTK_BOX(container), frame, FALSE, FALSE, 0);
    //    gtk_container_add(GTK_CONTAINER(frame), tree_view);
    //    gtk_widget_show(frame);
    //}
    //else
        gtk_box_pack_start(GTK_BOX(container), tree_view, FALSE, FALSE, 0);
    gtk_widget_show(tree_view);

    g_signal_connect(tree_view, "focus-in-event",
            G_CALLBACK(on_tree_view_focus), self);
    g_signal_connect(self->pv->renderer, "data-changed",
            G_CALLBACK(on_cert_changed), tree_view);
    GtkTreeSelection *tree_sel = 
            gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
    g_signal_connect(tree_sel, "changed", 
            G_CALLBACK(on_tree_selection_changed), self);

    if (idx == 0) // new chain
        gtk_tree_selection_select_iter(tree_sel, &iter);

    /* first column */
    GtkCellRenderer *tree_renderer = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *tree_column
        = gtk_tree_view_column_new_with_attributes(_("Certificate Hierarchy"),
                                        tree_renderer, "text", COL_NAME, NULL);
    gtk_tree_view_column_set_expand (tree_column, TRUE);
    gtk_tree_view_insert_column (GTK_TREE_VIEW (tree_view), tree_column, -1);

    /* second column */
    GtkCellRenderer *toggle_renderer = gtk_cell_renderer_toggle_new();
    g_signal_connect(toggle_renderer, "toggled",
                     G_CALLBACK(on_radio_toggled), tree_store);
    gtk_cell_renderer_toggle_set_radio(GTK_CELL_RENDERER_TOGGLE(toggle_renderer),
                                       TRUE);

    gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(tree_view), -1,
                                                _("Pin"), toggle_renderer,
                                                "active", COL_PIN, NULL);
    g_object_unref(tree_store);
}

void
patrol_dialog_window_load (PatrolDialogWindow *self, const gchar *host,
                           const gchar *proto, guint16 port, GList *chains,
                           gint chain_result, gint dane_result,
                           gint dane_status, gchar *app_name)
{
    PatrolDialogWindowPrivate *pv = self->pv;
    pv->host = host;
    pv->proto = proto;
    pv->port = port;
    pv->chains = chains;

    if (!chains)
        return;

    /* msg */
    gtk_image_set_from_stock(GTK_IMAGE(pv->icon),
                             (g_list_length(chains) > 1)
                             ? GTK_STOCK_DIALOG_WARNING
                             : GTK_STOCK_DIALOG_INFO,
                             GTK_ICON_SIZE_DIALOG);

    gchar *text = g_strdup_printf(
        g_list_length(chains) > 1
        ? _("<b>Public key change</b> detected for peer <b>%s:%u (%s)</b>\n"
            "in application <b>%s</b>\n")
        : _("<b>New public key</b> detected for peer <b>%s:%u (%s)</b>\n"
            "in application <b>%s</b>\n"),
        host, port, proto, app_name);
    gtk_label_set_markup(GTK_LABEL(pv->msg), text);
    g_free(text);

    /* chain_msg */
    if (chain_result != PATROL_ARG_UNKNOWN) {
        gtk_image_set_from_stock(GTK_IMAGE(pv->chain_icon),
                                 (chain_result == PATROL_OK)
                                 ? GTK_STOCK_APPLY
                                 : GTK_STOCK_DIALOG_ERROR,
                                 GTK_ICON_SIZE_BUTTON);

        text = g_strdup_printf(
            "<b>%s</b>: %s.",
            _("Certificate chain validation"),
            chain_result == PATROL_OK ? _("Success") : _("Fail"));
        gtk_label_set_markup(GTK_LABEL(pv->chain_msg), text);
        g_free(text);
    } else {
        gtk_widget_hide(gtk_widget_get_parent(pv->chain_msg));
    }

#ifdef HAVE_GNUTLS_DANE
    /* dane_msg */
    if (dane_result != PATROL_ARG_UNKNOWN) {
        gtk_image_set_from_stock(GTK_IMAGE(pv->dane_icon),
                                 (dane_result == DANE_E_SUCCESS)
                                 ? GTK_STOCK_APPLY
                                 : (dane_result == DANE_E_NO_DANE_DATA)
                                 ? GTK_STOCK_DIALOG_INFO
                                 : (dane_status == 0)
                                 ? GTK_STOCK_DIALOG_WARNING
                                 : GTK_STOCK_DIALOG_ERROR,
                                 GTK_ICON_SIZE_BUTTON);

        gnutls_datum_t dane_status_str = { 0 };
        if (dane_result >= 0 || dane_status != 0)
            dane_verification_status_print(dane_status, &dane_status_str, 0);
        text = g_strdup_printf(
            "<b>%s</b>: %s %.*s",
            _("DANE validation"),
            dane_strerror(dane_result),
            dane_status_str.size, dane_status_str.data);
        gnutls_free(dane_status_str.data);

        gtk_label_set_markup(GTK_LABEL(pv->dane_msg), text);
        g_free(text);
    } else {
        gtk_widget_hide(gtk_widget_get_parent(pv->dane_msg));
    }
#endif

    GList *item = chains;
    guint i = 0;
    while (item) {
        load_chain(self, item->data, i, i ? pv->old_chains : pv->new_chain);
        item = item->next;
        i++;
    }
}

static void
patrol_dialog_window_init (PatrolDialogWindow *self)
{
    PatrolDialogWindowPrivate *pv
        = self->pv = G_TYPE_INSTANCE_GET_PRIVATE(self, PATROL_TYPE_DIALOG_WINDOW,
                                                 PatrolDialogWindowPrivate);
    pv->host = NULL;
    pv->proto = NULL;
    pv->port = 0;
    pv->chains = NULL;

    pv->renderer = gcr_certificate_renderer_new(NULL);
    pv->viewer = gcr_viewer_new_scrolled();
    gcr_viewer_add_renderer(pv->viewer, GCR_RENDERER(pv->renderer));
}

static void
patrol_dialog_window_class_init (PatrolDialogWindowClass *cls)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS (cls);

    gobject_class->constructed = patrol_dialog_window_constructed;

    g_type_class_add_private(cls, sizeof(PatrolDialogWindow));

    signals[SIGNAL_ACCEPT]
        = g_signal_new("accept", PATROL_TYPE_DIALOG_WINDOW, G_SIGNAL_RUN_LAST,
                       0, NULL, NULL, NULL, G_TYPE_NONE, 0);

    signals[SIGNAL_ACCEPT_ADD]
        = g_signal_new("accept-add", PATROL_TYPE_DIALOG_WINDOW, G_SIGNAL_RUN_LAST,
                       0, NULL, NULL, NULL, G_TYPE_NONE, 0);

    signals[SIGNAL_CONTINUE]
        = g_signal_new("continue", PATROL_TYPE_DIALOG_WINDOW, G_SIGNAL_RUN_LAST,
                       0, NULL, NULL, NULL, G_TYPE_NONE, 0);

    signals[SIGNAL_REJECT]
        = g_signal_new("reject", PATROL_TYPE_DIALOG_WINDOW, G_SIGNAL_RUN_LAST,
                       0, NULL, NULL, NULL, G_TYPE_NONE, 0);
}

PatrolDialogWindow *
patrol_dialog_window_new (const gchar *host, const gchar *proto,
                          guint16 port, GList *chains,
                          gint chain_result, gint dane_result,
                          gint dane_status, gchar *app_name)
{
    PatrolDialogWindow *self = g_object_new(PATROL_TYPE_DIALOG_WINDOW, NULL);
    patrol_dialog_window_load(self, host, proto, port, chains, chain_result,
                              dane_result, dane_status, app_name);
    return self;
}

