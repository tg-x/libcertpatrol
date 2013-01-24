#ifndef PATROL_DIALOG_H
# define PATROL_DIALOG_H

#include <gcr/gcr.h>

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
