#include "config.h"
#include "common.h"
#include "dialog.h"
#include "dialog-window.h"

#include <glib/gi18n-lib.h>
#include <gtk/gtk.h>
#include <gcr/gcr.h>

#include <locale.h>
#include <string.h>

struct _PatrolDialogWindowPrivate {
    const gchar *host;
    const gchar *proto;
    gint16 port;
    GList *chains;

    gboolean add;

    GtkWidget *msg;
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
    gtk_window_set_default_size(GTK_WINDOW(self), 500, 500);
    //gtk_window_set_position(GTK_WINDOW(self), GTK_WIN_POS_MOUSE);

    /* content area */
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_left(GTK_WIDGET(content), 6);
    gtk_widget_set_margin_right(GTK_WIDGET(content), 6);
    gtk_container_add(GTK_CONTAINER(self), content);
    gtk_widget_show(content);

    /* message */
    pv->msg = gtk_label_new(NULL);
    gtk_widget_set_halign(GTK_WIDGET(pv->msg), GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(content), pv->msg, FALSE, FALSE, 6);
    gtk_widget_show(pv->msg);

    /* details: chains & cert viewer */
    GtkWidget *details = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(content), details, FALSE, FALSE, 6);
    gtk_widget_show(GTK_WIDGET(details));

    GtkWidget *chains = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_box_pack_start(GTK_BOX(details), chains, FALSE, FALSE, 0);
    gtk_widget_show(GTK_WIDGET(chains));

    pv->new_chain = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_box_pack_start(GTK_BOX(chains), pv->new_chain, FALSE, FALSE, 0);
    gtk_widget_show(GTK_WIDGET(pv->new_chain));

    //pv->old_chains = gtk_layout_new(NULL, NULL);
    pv->old_chains = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_box_pack_start(GTK_BOX(chains), pv->old_chains, TRUE, TRUE, 0);
    gtk_widget_show(GTK_WIDGET(pv->old_chains));

    gtk_box_pack_start(GTK_BOX(details), GTK_WIDGET(pv->viewer), TRUE, TRUE, 0);
    gtk_widget_show(GTK_WIDGET(pv->viewer));

    /* additional pin checkbox */
    GtkWidget *add = gtk_check_button_new_with_mnemonic(
        _("_Store additional pin instead of replacing existing ones"));
    gtk_widget_show(add);
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
    gtk_box_pack_start(GTK_BOX(bbox), btn, FALSE, TRUE, 0);
    g_signal_connect_object (GTK_BUTTON(btn), "clicked",
                             G_CALLBACK(on_reject_clicked), self, 0);

    /* continue button */
    btn = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
    gtk_button_set_label(GTK_BUTTON(btn), _("_Continue"));
    gtk_box_pack_start(GTK_BOX(bbox), btn, FALSE, TRUE, 0);
    g_signal_connect_object(GTK_BUTTON(btn), "clicked",
                            G_CALLBACK(on_continue_clicked), self, 0);
    gtk_widget_grab_focus(btn);

    /* accept button */
    btn = gtk_button_new_from_stock(GTK_STOCK_YES);
    gtk_button_set_label(GTK_BUTTON(btn), _("_Accept"));
    gtk_box_pack_start(GTK_BOX(bbox), btn, FALSE, TRUE, 0);
    g_signal_connect_object(GTK_BUTTON(btn), "clicked",
                            G_CALLBACK(on_accept_clicked), self, 0);

    gtk_widget_show_all(bbox);
}

static gboolean
on_tree_view_focus (GtkWidget *tree_view, GtkDirectionType direction, gpointer arg) {
    PatrolDialogWindow *self = PATROL_DIALOG_WINDOW(arg);
    GcrCertificate *cert;
    GtkTreeSelection *tree_selection;
    GtkTreeIter iter;
    GtkTreeModel *tree_model;

    tree_selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));

    if (gtk_tree_selection_get_selected(tree_selection, &tree_model, &iter)) {
        gtk_tree_model_get(tree_model, &iter, COL_CERT, &cert, -1);
        gcr_certificate_renderer_set_certificate(self->pv->renderer, cert);
    }
    return FALSE;
}

static void
on_tree_selection_changed (GtkTreeSelection *tree_selection, gpointer arg) {
    PatrolDialogWindow *self = PATROL_DIALOG_WINDOW(arg);
    GcrCertificate *cert;
    GtkTreeIter iter;
    GtkTreeModel *tree_model;

    if (gtk_tree_selection_get_selected(tree_selection, &tree_model, &iter)) {
        gtk_tree_model_get(tree_model, &iter, COL_CERT, &cert, -1);
        gcr_certificate_renderer_set_certificate(self->pv->renderer, cert);
    }
}

static void
on_radio_toggled (GtkCellRendererToggle *renderer, gchar *path_str, gpointer arg) {
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

    /* build tree viewer */
    GtkWidget *tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(tree_store));
    gtk_tree_view_expand_all(GTK_TREE_VIEW(tree_view));
    g_signal_connect(tree_view, "focus-in-event", G_CALLBACK(on_tree_view_focus), self);

    GtkTreeSelection *tree_sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
    g_signal_connect(tree_sel, "changed", G_CALLBACK(on_tree_selection_changed), self);
    gtk_box_pack_start(GTK_BOX(container), tree_view, FALSE, FALSE, 0);
    gtk_widget_show(tree_view);
    if (idx == 0) // new chain
        gtk_tree_selection_select_iter(tree_sel, &iter);

    /* first column */
    GtkCellRenderer *tree_renderer = gtk_cell_renderer_text_new();
    gtk_tree_view_insert_column_with_attributes(
        GTK_TREE_VIEW(tree_view), -1, _("Certificate Hierarchy"),
        tree_renderer, "text", COL_NAME, NULL
    );

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
                           const gchar *proto, guint16 port, GList *chains)
{
    PatrolDialogWindowPrivate *pv = self->pv;
    pv->host = host;
    pv->proto = proto;
    pv->port = port;
    pv->chains = chains;

    if (!chains)
        return;

    gchar *text = g_strdup_printf(
        g_list_length(chains) > 1
        ? _("New public key detected for peer %s:%u (%s).\n"
            "Accept it and pin it, reject it, or continue and decide later?")
        : _("Public key change detected for peer %s:%u (%s).\n"
            "Accept it and replace the pin, accept it and add as additional pin, "
            "reject it, or continue and decide later?"),
        host, port, proto);
    gtk_label_set_text(GTK_LABEL(pv->msg), text);
    g_free(text);

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
                          guint16 port, GList *chains)
{
    PatrolDialogWindow *self = g_object_new(PATROL_TYPE_DIALOG_WINDOW, NULL);
    patrol_dialog_window_load(self, host, proto, port, chains);
    return self;
}

