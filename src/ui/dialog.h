#ifndef PATROL_DIALOG_H
# define PATROL_DIALOG_H

#include "lib/patrol.h"

#include <gtk/gtk.h>
#include <gcr/gcr.h>

#define PATROL_ARG_UNKNOWN G_MAXINT

typedef struct {
    gboolean pin_changed;
    int pin_level;
    GcrCertificateChain *chain;
    PatrolRecord rec;
} PatrolDialogRecord;

#endif
