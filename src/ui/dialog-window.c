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
};

G_DEFINE_TYPE(PatrolDialogWindow, patrol_dialog_window, GTK_TYPE_WINDOW);

static void
patrol_dialog_window_constructed (GObject *obj)
{
    PatrolDialogWindow *self = PATROL_DIALOG_WINDOW(obj);
    G_OBJECT_CLASS(patrol_dialog_window_parent_class)->constructed(obj);
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
