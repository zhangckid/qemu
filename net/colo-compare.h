#ifndef QEMU_COLO_COMPARE_H
#define QEMU_COLO_COMPARE_H

void colo_notify_compares_event(void *opaque, int event, Error **errp);
void colo_compare_register_notifier(Notifier *notify);
void colo_compare_unregister_notifier(Notifier *notify);

#endif /* QEMU_COLO_COMPARE_H */
