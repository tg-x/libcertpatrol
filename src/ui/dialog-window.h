#ifndef PATROL_DIALOG_WINDOW_H
#define PATROL_DIALOG_WINDOW_H

#include <certpatrol/patrol.h>
#include <gtk/gtk.h>

#define PATROL_TYPE_DIALOG_WINDOW \
    (patrol_dialog_window_get_type())
#define PATROL_DIALOG_WINDOW(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), PATROL_TYPE_DIALOG_WINDOW, PatrolDialogWindow))
#define PATROL_DIALOG_WINDOW_CLASS(cls) \
    (G_TYPE_CHECK_CLASS_CAST((cls), PATROL_TYPE_DIALOG_WINDOW, PatrolDialogWindowClass))
#define PATROL_IS_DIALOG_WINDOW(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), PATROL_TYPE_DIALOG_WINDOW))
#define PATROL_IS_DIALOG_WINDOW_CLASS(cls) \
    (G_TYPE_CHECK_CLASS_TYPE((cls), PATROL_TYPE_DIALOG_WINDOW))
#define PATROL_DIALOG_WINDOW_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), PATROL_TYPE_DIALOG_WINDOW, PatrolDialogWindowClass))

typedef struct _PatrolDialogWindow PatrolDialogWindow;
typedef struct _PatrolDialogWindowClass PatrolDialogWindowClass;
typedef struct _PatrolDialogWindowPrivate PatrolDialogWindowPrivate;

struct _PatrolDialogWindow {
	GtkWindow parent;
	PatrolDialogWindowPrivate *pv;
};

struct _PatrolDialogWindowClass {
	GtkWindowClass parent_class;
};

GType
patrol_dialog_window_get_type (void);

PatrolDialogWindow *
patrol_dialog_window_new (const gchar *host, const gchar *proto,
                          guint16 port, GList *chain_list);

#endif
