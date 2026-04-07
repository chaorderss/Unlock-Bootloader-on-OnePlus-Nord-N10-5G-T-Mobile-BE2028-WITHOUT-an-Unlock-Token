/*
 * Patch nl80211_tx_mgmt iftype bitmask in running kernel.
 * Changes MOVZ W11, #0x39e to MOVZ W11, #0x3de (adds MONITOR bit 6).
 *
 * This is a userspace program that calls kernel functions
 * via function pointers obtained from /proc/kallsyms.
 * Must run as root.
 *
 * Approach: set_memory_rw(page, 1) then write, then set_memory_ro(page, 1)
 * This works because root can read /proc/kallsyms and get real addresses,
 * and the kernel virtual addresses are directly accessible from userspace...
 * Actually no - kernel addresses are NOT accessible from userspace.
 *
 * Alternative: Write a loadable kernel module (.ko) directly in machine code.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    printf("This approach (userspace calling kernel functions) won't work.\n");
    printf("Need a kernel module or /dev/mem access.\n");
    return 1;
}
