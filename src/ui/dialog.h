#ifndef PATROL_DIALOG_H
# define PATROL_DIALOG_H

#include <gtk/gtk.h>
#include <gcr/gcr.h>

#define PATROL_ARG_UNKNOWN G_MAXINT

typedef struct {
    GcrCertificateChain *chain;
    GtkWidget *tree;
    GtkTreeStore *tree_store;
}  PatrolDialogChain;

typedef struct {
    GckAttributes *attrs;
    GcrCertificate *cert;
    GcrCertificateWidget *widget;
    PatrolDialogChain *chain;
} PatrolDialogCert;

#endif
