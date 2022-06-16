#ifndef _CONFIG_H_
#define _CONFIG_H_

#define VERSION "1.00a"

#define MAP_NUM 0x40
#define PROC_NUM 0x100
#define PAGE_SIZE 0x1000
#define __ID__ "SCSLSCSL"

#define OFFSET_uid_from_cred 0x04
#define OFFSET_gid_from_cred 0x08
#define OFFSET_euid_from_cred 0x14
#define OFFSET_egid_from_cred 0x18

int verbose __attribute__((weak)) = 1;

#endif /* _CONFIG_H_ */