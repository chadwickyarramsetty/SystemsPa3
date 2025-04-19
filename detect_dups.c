// add any other includes in the detetc_dups.h file
#include "detect_dups.h"
#include <openssl/md5.h>
#include "uthash.h"
#include <ftw.h>
#include <unistd.h>  // For readlink and realpath

// define any other global variable you may need 

typedef struct path_node {
    char *path;
    struct path_node *next;
    ino_t inode;
} pathn;
typedef struct pending_symlink {
    char path[PATH_MAX];
    char resolved[PATH_MAX];
    struct pending_symlink *next;
} PendSym;

PendSym *pending_symlinks = NULL;

typedef struct symlink_group{
    int count;
    ino_t inode;
    pathn *paths;
    struct symlink_group *next;
}symGroup;

typedef struct inode_group {
    ino_t inode;
    int count;
    pathn *paths;
    symGroup *symlinks;
    struct inode_group *next;
} inodeGroup;

typedef struct file_entry {
    char md5[33];
    inodeGroup *inodes;
    pathn *symlinks;
    UT_hash_handle hh;
} fileEntry;

fileEntry *file_map = NULL;
// open ssl, this will be used to get the hash of the file
EVP_MD_CTX *mdctx;
const EVP_MD *EVP_md5(); // use md5 hash!!

void compMD5(const char *filename, char *output)
{
    const EVP_MD *md = EVP_md5();
    unsigned char buffer[1024];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashlength;
    size_t bytes;
    FILE *file = fopen(filename, "rb");

    if (!file)
    {
        //printf("symlink?\n");
        output[0] = '0';
        //perror("malloc");
        return;
    }


    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);

    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        EVP_DigestUpdate(mdctx, buffer, bytes);
    }

    EVP_DigestFinal_ex(mdctx, hash, &hashlength);
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    for (unsigned int i = 0; i < hashlength; ++i)
    {
        sprintf(&output[i * 2], "%02x", hash[i]);
    }

    output[32] = '\0';

}

void expectedprint() {
    fileEntry *entry, *tmp;
    int file_number = 1;

    HASH_ITER(hh, file_map, entry, tmp) {
        printf("File %d\n", file_number++);
        printf("\tMD5 Hash: %s\n", entry->md5);

        inodeGroup *group = entry->inodes;
        int hardsetnum = 1;

        while (group) {
            int softcount = 1;
            printf("\tHard Link (%d): %lu\n", group->count, group->inode);
            pathn *p = group->paths;
            int tf = 0;
            while (p) {
                printf(tf == 0 ? "\t\tPaths:\t%s\n" : "\t\t\t%s\n", p->path);
                tf = 1;
                p = p->next;
            }

            if (group->symlinks) {
                symGroup *symlinkgrp = group->symlinks;
                
                while(symlinkgrp)
                {
                    int count = 0;
                    pathn *p = symlinkgrp->paths;

                    while (p)
                    {
                        count++;
                        p = p->next;
                    }

                    printf("\t\tSoft Link %d(%d): %lu\n", softcount++, count, symlinkgrp->inode);

                    p = symlinkgrp->paths;

                    int tf = 0;

                    while (p)
                    {
                        printf(tf == 0 ? "\t\t\tPaths:\t%s\n" : "\t\t\t%s\n", p->path);
                        tf = 1;
                        p = p->next;
                    }

                    symlinkgrp = symlinkgrp->next;
                }
                /*int count = 0;
                pathn *temp = group->symlinks;
                while (temp) {
                    count++;
                    temp = temp->next;
                }
                temp = group->symlinks;

                while (temp)
                {
                    temp = temp->next;
                }
                /*printf("\t\tSoft Link %d(%d): %lu\n", softcount++, count, group->symlinks->inode);
                temp = group->symlinks;
                tf = 0;
                while (temp) {
                    printf(tf == 0 ? "\t\t\tPaths:\t%s\n" : "\t\t\t%s\n", temp->path);
                    tf = 1;
                    temp = temp->next;
                }*/
            }

            group = group->next;
            hardsetnum++;
        }
    }
}

void isDup(const char *md5, const char *path, const struct stat *sb)
{
    fileEntry *entry = NULL;
    HASH_FIND_STR(file_map, md5, entry);

    if (!entry) {
        // New MD5
        entry = calloc(1, sizeof(fileEntry));
        strncpy(entry->md5, md5, sizeof(entry->md5));

        inodeGroup *group = calloc(1, sizeof(inodeGroup));
        group->inode = sb->st_ino;
        group->count = 1;
        group->paths = NULL;

        pathn *node = malloc(sizeof(pathn));
        node->path = strdup(path);
        node->next = NULL;
        group->paths = node;

        entry->inodes = group;

        HASH_ADD_STR(file_map, md5, entry);
    } else {
        inodeGroup *group = entry->inodes;
        while (group) {
            if (group->inode == sb->st_ino) {

                group->count++;
                pathn *node = malloc(sizeof(pathn));
                node->path = strdup(path);
                node->next = group->paths;
                group->paths = node;
                return;
            }
            group = group->next;
        }

        inodeGroup *new_group = calloc(1, sizeof(inodeGroup));
        new_group->inode = sb->st_ino;
        new_group->count = 1;

        pathn *node = malloc(sizeof(pathn));
        node->path = strdup(path);
        node->next = NULL;
        new_group->paths = node;

        new_group->next = entry->inodes;
        entry->inodes = new_group;
    }
}
void addSym(const char *md5, const char *symlink_path) {
    struct stat sb;
    struct stat sb2;
    if (lstat(symlink_path, &sb) != 0 || stat(symlink_path, &sb2) != 0)
    {
        perror("stat (symlink)");
        return;
    }

    fileEntry *entry;
    HASH_FIND_STR(file_map, md5, entry);
    //printf("Trying to add symlink: %s -> MD5: %s\n", symlink_path, md5);

    if (!entry){
        //printf("MD5 not found for symlink %s — probably target was not processed first.\n", symlink_path);
        return;
    } 

    //printf("%s\n", md5);

    inodeGroup *group = entry->inodes;
    while (group) {
        //printf("hello2\n");

        if (group->inode == sb2.st_ino)
        {
            symGroup *symgrp = group->symlinks;

            while (symgrp)
            {
                if (symgrp->inode == sb.st_ino)
                {
                    break;
                }
                symgrp = symgrp->next;
            }

            if (!symgrp)
            {
                symgrp = malloc(sizeof(symGroup));
                symgrp->inode = sb.st_ino;
                symgrp->paths = NULL;
                symgrp->next = group->symlinks;
                group->symlinks = symgrp;
            }
            //printf("hello2\n");

            pathn *newSym = malloc(sizeof(pathn));
            newSym->path = strdup(symlink_path);
            newSym->next = symgrp->paths;
            symgrp->paths = newSym;
            symgrp->count++;
            return;
        }

        group = group->next;
    }

    if (entry->inodes) {
        //printf("hello1111\n");
        /*pathn *newSym = malloc(sizeof(pathn));
        newSym->path = strdup(symlink_path);
        newSym->next = entry->inodes->symlinks;
        newSym->inode = sb.st_ino;
        entry->inodes->symlinks = newSym;*/
        symGroup *symgrp = malloc(sizeof(symGroup));
        symgrp->inode = sb.st_ino;
        symgrp->count = 1;
        symgrp->next = entry->inodes->symlinks;
        symgrp->paths = NULL;

        pathn *newPath = malloc(sizeof(pathn));
        newPath->path = strdup(symlink_path);
        newPath->next = NULL;
        newPath->inode = sb.st_ino;

        symgrp->paths = newPath;
        entry->inodes->symlinks = symgrp;
    }
}

// render the file information invoked by nftw
static int render_file_info(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf) {
    // perform the inode operations over here
    //printf("%s\n", fpath);

    if (tflag == FTW_F)
    {
        char md5[33];
        compMD5(fpath, md5);

        if (md5[0] != '\0')
        {
            isDup(md5, fpath, sb);
        }
    }

    else if (tflag == FTW_SL) {
        //printf("%s\n", fpath);

        //printf("Symlink target: %s\n", fpath);
        char target[PATH_MAX];
        ssize_t leng = readlink(fpath, target, sizeof(target) - 1);
        if (leng != -1) {
            target[leng] = '\0';  // Null-terminate it
            //printf("Symlink points to: %s\n", target);
        } else {
            perror("readlink");
        }
        // Optionally resolve full path
        char resPath[PATH_MAX];
        realpath(fpath, resPath);
        /*ssize_t len = readlink(fpath, resolved_path, sizeof(resolved_path) - 1);
        resolved_path[len] = '\0';*/
        //printf("hello\n");
        char md5[33];
        compMD5(resPath, md5);

        //printf("%s\n", md5);
        if (md5[0] != '\0') {
            fileEntry *entry;
            HASH_FIND_STR(file_map, md5, entry);

            if (entry)
            {
                addSym(md5, fpath);
            }
            else
            {
                PendSym *pend = malloc(sizeof(PendSym));
                strncpy(pend->path, fpath, PATH_MAX);
                strncpy(pend->resolved, resPath, PATH_MAX);
                pend->next = pending_symlinks;
                pending_symlinks = pend;
            }
            //addSym(md5, fpath);
        }
    }
    
    

    return 0;

    // invoke any function that you may need to render the file information
}

int main(int argc, char *argv[]) {
    // perform error handling, "exit" with failure incase an error occurs
    //printf("%s\n", argv[1]);
    int r = nftw(argv[1], render_file_info, 10, FTW_PHYS);

    PendSym *curr = pending_symlinks;

    while(curr)
    {
        char md5[33];
        compMD5(curr->resolved, md5);
        if (md5[0] != '\0')
        {
            addSym(md5, curr->path);
        }

        curr = curr->next;
    }

    expectedprint();

    //print_md5(file_hash->md5);
    //printf("hello");

    // initialize the other global variables you have, if any

    // add the nftw handler to explore the directory
    // nftw should invoke the render_file_info function
}

