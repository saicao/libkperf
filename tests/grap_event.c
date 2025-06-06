#include <kperf/kperf.h>
#include <stdio.h>
int main(int argc, char **argv) {
    int err = 0;
    // get current pid
    int force_ctrs = 0;
    if (kpc_force_all_ctrs_get(&force_ctrs)) {
        fprintf(stderr,"Permission denied, xnu/kpc requires root privileges.\n");
        return 1;
    }
    
    kpep_db *db = NULL;
    if ((err = kpep_db_create(NULL, &db))) {
        printf("Error: cannot load pmc database: %d.\n", err);
        return 1;
    }
    usize count=0;
    if ((err = kpep_db_events_count(db, &count))) {
        printf("Error: cannot get aliases count: %d.\n", err);
        return 1;
    }
    printf("Number of events: %zu\n", count);
    kpep_event *evnets[count];
    if ((err = kpep_db_events(db, evnets, sizeof(evnets)))) {
        printf("Error: cannot get events: %d.\n", err);
        return 1;
    }
    for(usize i = 0; i < count; i++) {
        kpep_event *ev = evnets[i];
        const char *name = NULL;
        const char *desc = NULL;
        kpep_event_name(ev, &name);
        kpep_event_description(ev, &desc);
        printf("Event %zu: %s (%s)\n", i, name, desc);
    }

}