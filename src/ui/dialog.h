#ifndef PATROL_DIALOG_H
# define PATROL_DIALOG_H

#include "lib/patrol.h"

#include <gtk/gtk.h>
#include <gcr/gcr.h>

#define PATROL_ARG_UNKNOWN G_MAXINT

typedef struct {
    gint64 id;
    PatrolStatus status;
    int pin_level;
    gboolean pin_changed;
    time_t pin_expiry;
    time_t first_seen;
    time_t last_seen;
    gint64 count_seen;
    PatrolData *der_chain;
    size_t der_chain_len;
    GcrCertificateChain *chain;
} PatrolDialogRecord;

#endif
