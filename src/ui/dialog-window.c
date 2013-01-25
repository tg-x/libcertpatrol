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
    GList *chain_list;
    gboolean add;
};

typedef enum {
    SIGNAL_ACCEPT,
    SIGNAL_ACCEPT_ADD,
    SIGNAL_CONTINUE,
    SIGNAL_REJECT,
    SIGNALS_NUM,
} PatrolDialogSignals;

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
    PatrolDialogWindow *self = PATROL_DIALOG_WINDOW(obj);
    GtkWidget *box, *bbox, *align_bbox, *btn, *add;

    G_OBJECT_CLASS(patrol_dialog_window_parent_class)->constructed(obj);

    gtk_window_set_title(GTK_WINDOW(self), _("Certificate Patrol"));

    /* button box */
    bbox = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_set_spacing(GTK_BOX(bbox), 12);
    gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_END);

    /* accept button */
    btn = gtk_button_new_from_stock(GTK_STOCK_YES);
    gtk_button_set_label(GTK_BUTTON(btn), _("Accept"));
    gtk_box_pack_start(GTK_BOX(bbox), btn, FALSE, TRUE, 0);
    g_signal_connect_object(GTK_BUTTON(btn), "clicked",
                            G_CALLBACK(on_accept_clicked), self, 0);

    /* continue button */
    btn = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
    gtk_button_set_label(GTK_BUTTON(btn), _("Continue"));
    gtk_box_pack_start(GTK_BOX(bbox), btn, FALSE, TRUE, 0);
    g_signal_connect_object(GTK_BUTTON(btn), "clicked",
                            G_CALLBACK(on_continue_clicked), self, 0);

    /* reject button */
    btn = gtk_button_new_from_stock(GTK_STOCK_NO);
    gtk_button_set_label(GTK_BUTTON(btn), _("Reject"));
    gtk_box_pack_start(GTK_BOX(bbox), btn, FALSE, TRUE, 0);
    g_signal_connect_object (GTK_BUTTON(btn), "clicked",
                             G_CALLBACK(on_reject_clicked), self, 0);

    add = gtk_check_button_new_with_mnemonic(_("Store additional pin instead of "
                                               "replacing existing ones"));
    gtk_widget_show(add);
    g_signal_connect_object(GTK_TOGGLE_BUTTON(add), "toggled",
                            G_CALLBACK(on_add_toggled), self, 0);

    /* alignment widget (containing bbox) */
    align_bbox = gtk_alignment_new(0.5, 0.5, 1.0, 1.0);
    gtk_alignment_set_padding(GTK_ALIGNMENT(align_bbox), 0, 0, 0, 12);
    gtk_container_add(GTK_CONTAINER(align_bbox), bbox);
    gtk_widget_show_all(align_bbox);

    /* container box */
    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_show(box);
    gtk_box_pack_end(GTK_BOX(box), align_bbox, FALSE, FALSE, 6);
    gtk_box_pack_end(GTK_BOX(box), add, FALSE, FALSE, 6);
    gtk_container_add(GTK_CONTAINER(self), box);

    gtk_window_set_default_size(GTK_WINDOW(self), 350, 500);
}

static void
patrol_dialog_window_init (PatrolDialogWindow *self)
{
    self->pv = G_TYPE_INSTANCE_GET_PRIVATE(self, PATROL_TYPE_DIALOG_WINDOW,
                                           PatrolDialogWindowPrivate);
}

static void
patrol_dialog_window_class_init (PatrolDialogWindowClass *cls)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS (cls);

    gobject_class->constructed = patrol_dialog_window_constructed;

    g_type_class_add_private (cls, sizeof (PatrolDialogWindow));

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
                          guint16 port, GList *chain_list)
{
    PatrolDialogWindow *self = g_object_new (PATROL_TYPE_DIALOG_WINDOW, NULL);
    self->pv->host = host;
    self->pv->proto = proto;
    self->pv->port = port;
    self->pv->chain_list = chain_list;
    return self;
}
