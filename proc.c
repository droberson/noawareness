#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>

#include <linux/limits.h>

#include "proc.h"
#include "string_common.h"


char *proc_exe_path(pid_t pid) {
    static char exe_path[PATH_MAX];

    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    return exe_path;
}

char *proc_get_exe_path(pid_t pid) {
    char        exe_path[PATH_MAX];
    static char real_path[PATH_MAX];

    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);

    memset(real_path, 0x00, sizeof(real_path));

    if (readlink(exe_path, real_path, PATH_MAX) == -1) {
        fprintf(stderr, "readlink (%s): %s\n", exe_path, strerror(errno));
    }

    return real_path;
}

char *proc_get_cmdline(pid_t pid) {
    // had to do it this way because /proc/X/cmdline stores arguments with
    // a null as a separator instead of spaces or whatever. can probably
    // do something better
    int             fd;
    int             i;
    char            cmdline_path[PATH_MAX];
    static char     buf[ARG_MAX];
    int             bytes;

    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);

    memset(buf, 0x00, sizeof(buf));
    fd = open(cmdline_path, O_RDONLY);
    bytes = read(fd, buf, sizeof(buf));
    close(fd);

    for (i = 0; i < bytes - 1; i++) {
        if (buf[i] == 0x00) {
            buf[i] = ' ';
        }
    }

    return buf;
}

/*
Name:   rtkit-daemon
Umask:  0777
State:  S (sleeping)
Tgid:   736
Ngid:   0
Pid:    736
PPid:   1a
TracerPid:      0
Uid:    119     119     119     119
Gid:    123     123     123     123
FDSize: 128
Groups:
NStgid: 736
NSpid:  736
NSpgid: 736
NSsid:  736
VmPeak:   224416 kB
VmSize:   158880 kB
VmLck:         0 kB
VmPin:         0 kB
VmHWM:      3040 kB
VmRSS:      2768 kB
RssAnon:             276 kB
RssFile:            2492 kB
RssShmem:              0 kB
VmData:    16976 kB
VmStk:       132 kB
VmExe:        60 kB
VmLib:      3360 kB
VmPTE:        72 kB
VmSwap:        0 kB
HugetlbPages:          0 kB
CoreDumping:    0
Threads:        3
SigQ:   0/31680
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000000000
SigIgn: 0000000000001000
SigCgt: 0000000180000000
CapInh: 0000000000000000
CapPrm: 0000000000800004
CapEff: 0000000000800004
CapBnd: 00000000008c00c4
CapAmb: 0000000000000000
NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       thread vulnerable
Cpus_allowed:   ffffffff,ffffffff,ffffffff,ffffffff
Cpus_allowed_list:      0-127
Mems_allowed:   00000000,00000001
Mems_allowed_list:      0
voluntary_ctxt_switches:        98
nonvoluntary_ctxt_switches:     46
*/

struct proc_status proc_get_status(pid_t pid) {
    FILE                *fp;
    struct proc_status  result;
    char                proc_status[PATH_MAX];
    char                buf[1024];

    snprintf(proc_status, sizeof(proc_status), "/proc/%d/status", pid);

    fp = fopen(proc_status, "r");
    if (fp == NULL) {
        fprintf(stderr, "error opening %s: %s\n", proc_status, strerror(errno));
        memset(result.name, 0x00, sizeof(result.name));
        return result;
    }

    while(fgets(buf, sizeof(buf), fp) != NULL) {
        /*
         * use a switch on the first letter so we arent parsing every line
         * like a villager.
         */
        switch (buf[0]) {
            case 'G':
                if (startswith(buf, "Gid:")) {
                    sscanf(buf, "Gid:\t%d\t%d\t%d\t%d\n",
                        &result.gid,
                        &result.egid,
                        &result.ssgid,
                        &result.fsgid);
                }
                break;

            case 'N':
                if (startswith(buf, "Name:")) {
                    sscanf(buf, "Name:\t%s\n", result.name);
                }
                break;

            case 'U':
                if (startswith(buf, "Uid:")) {
                    sscanf(buf, "Uid:\t%d\t%d\t%d\t%d\n",
                        &result.uid,
                        &result.euid,
                        &result.ssuid,
                        &result.fsuid);
                }
                break;

            default:
                //printf("%s", buf);
                break;
        }
    }

    fclose(fp);

    return result;
}

