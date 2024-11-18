#pragma once

/*
Name:   rtkit-daemon
Umask:  0777
State:  S (sleeping)
Tgid:   736
Ngid:   0
Pid:    736
PPid:   1
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

struct proc_status {
    char    name[1024];
    uid_t   uid;
    uid_t   euid;
    uid_t   ssuid;
    uid_t   fsuid;
    gid_t   gid;
    gid_t   egid;
    gid_t   ssgid;
    gid_t   fsgid;
};

char *proc_cwd(pid_t);
char *proc_environ(pid_t);
char *proc_exe_path(pid_t);
char *proc_get_exe_path(pid_t);
char *proc_get_cmdline(pid_t);
struct proc_status proc_get_status(pid_t);
