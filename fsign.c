
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include "acl.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int isdir(char* path) 
{
    struct stat path_stat;
    if(stat(path,&path_stat)!=0) {
        printf("%s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    return S_ISDIR(path_stat.st_mode);
}

struct acl *load_acl(char *path)
{
    struct acl *meta = (struct acl *)malloc(sizeof(struct acl));
    int size;
    char buf[0];
    int bool_isdir = 0;
    
    
    bool_isdir = isdir(path);


    size = getxattr(path, OWNER, &buf, 0);
    ////acl_present(size);
    char *owner = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, OWNER, owner, size);
    owner[size] = '\0';

    size = getxattr(path, NAMED_USERS, &buf, 0);
    ////acl_present(size);
    char *named_users = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, NAMED_USERS, named_users, size);
    named_users[size] = '\0';

    size = getxattr(path, OWNER_GROUP, &buf, 0);
    ////acl_present(size);
    char *owner_group = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, OWNER_GROUP, owner_group, size);
    owner_group[size] = '\0';

    size = getxattr(path, NAMED_GROUPS, &buf, 0);
    ////acl_present(size);
    char *named_groups = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, NAMED_GROUPS, named_groups, size);
    named_groups[size] = '\0';

    size = getxattr(path, MASK, &buf, 0);
    ////acl_present(size);
    char *mask = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, MASK, mask, size);
    mask[size] = '\0';

    size = getxattr(path, OTHERS, &buf, 0);
    ////acl_present(size);
    char *others = (char *)malloc((size + 1) * sizeof(char));
    size = getxattr(path, OTHERS, others, size);
    others[size] = '\0';

    meta->isdir = bool_isdir;
    meta->owner = owner;
    meta->named_users = named_users;
    meta->onwer_group = owner_group;
    meta->named_groups = named_groups;
    meta->mask = mask;
    meta->others = others;

    if (bool_isdir==1) 
    {

        size = getxattr(path, DEFAULT_OWNER, &buf, 0);
        ////acl_present(size);
        char *default_owner = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_OWNER, default_owner, size);
        default_owner[size] = '\0';

        size = getxattr(path, DEFAULT_NAMED_USERS, &buf, 0);
        ////acl_present(size);
        char *default_named_users = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_NAMED_USERS, default_named_users, size);
        default_named_users[size] = '\0';

        size = getxattr(path, DEFAULT_OWNER_GROUP, &buf, 0);
        ////acl_present(size);
        char *default_owner_group = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_OWNER_GROUP, default_owner_group, size);
        default_owner_group[size] = '\0';

        size = getxattr(path, DEFAULT_NAMED_GROUPS, &buf, 0);
        ////acl_present(size);
        char *default_named_groups = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_NAMED_GROUPS, default_named_groups, size);
        default_named_groups[size] = '\0';

        size = getxattr(path, DEFAULT_MASK, &buf, 0);
        ////acl_present(size);
        char *default_mask = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_MASK, default_mask, size);
        default_mask[size] = '\0';

        size = getxattr(path, DEFAULT_OTHERS, &buf, 0);
        ////acl_present(size);
        char *default_others = (char *)malloc((size + 1) * sizeof(char));
        size = getxattr(path, DEFAULT_OTHERS, default_others, size);
        default_others[size] = '\0';

        meta->default_owner = default_owner;
        meta->default_named_users = default_named_users;
        meta->default_onwer_group = default_owner_group;
        meta->default_named_groups = default_named_groups;
        meta->default_mask = default_mask;
        meta->default_others = default_others;
    
    }

    return meta;
}

void save_acl(char* path, struct acl* meta) {

    // printf("owner : %s\n",meta->owner);
    if (setxattr(path, OWNER, meta->owner, strlen(meta->owner), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, NAMED_USERS, meta->named_users, strlen(meta->named_users), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, OWNER_GROUP, meta->onwer_group, strlen(meta->onwer_group), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, NAMED_GROUPS, meta->named_groups, strlen(meta->named_groups), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, MASK, meta->mask, strlen(meta->mask), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, OTHERS, meta->others, strlen(meta->others), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if(meta->isdir==0){
        return;
    }
    if (setxattr(path, DEFAULT_OWNER, meta->default_owner, strlen(meta->default_owner), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, DEFAULT_NAMED_USERS, meta->default_named_users, strlen(meta->default_named_users), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, DEFAULT_OWNER_GROUP, meta->default_onwer_group, strlen(meta->default_onwer_group), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, DEFAULT_NAMED_GROUPS, meta->default_named_groups, strlen(meta->default_named_groups), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, DEFAULT_MASK, meta->default_mask, strlen(meta->default_mask), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setxattr(path, DEFAULT_OTHERS, meta->default_others, strlen(meta->default_others), 0) != 0)
    {
        printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return;
}

char* getOwnerName(char* uname, char* filename){
    uid_t uid;

    if(access(filename,F_OK)!=0) {
        uid = getuid();
    }
    else {
        struct stat filestat;
        if(stat(filename,&filestat)!=0) {
            printf("%s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }
        uid = filestat.st_uid;
    }

    struct passwd* user;
    user = getpwuid(uid);
    
    char* username = user->pw_name;
    int size = strlen(username)+1;
    uname = realloc(uname,sizeof(char)*size);
    strcpy(uname,username);

    return uname;
}

int readShadow(char* uname, char** saltptr, char** passptr){

    FILE *f;
    f = fopen("/etc/shadow","r");
    if(f==NULL) {
        printf("Cannot open /etc/shadow/.\n");
        exit(0);
    }

    fseek(f,0L,SEEK_END);
    long int size = ftell(f);
    fclose(f);

    // printf("%ld\n",size);
    f = fopen("/etc/shadow","r");
    if(f==NULL) {
        printf("Cannot open /etc/shadow/.\n");
        exit(EXIT_FAILURE);
    }

    char buff[size+1];
    char c;
    long int i=0;
    c = fgetc(f);
    while(c!=EOF) {
        buff[i++] = c;
        c = fgetc(f);
    }
    buff[i++]='\0';
    fclose(f);
    // printf("%s\n",buff);

    i=0;
    char* pass;
    char* salt;
    while(i<=size) {
        if(buff[i]==uname[0]){
            long int j = i; 
            int k = 0;
            int namelen = strlen(uname);
            while(buff[j++]==uname[k++]) {
                if(k==namelen) break;
            }
            if(k!=namelen) {i++;continue;}

            int cdollar = 0;
            while(cdollar<2) {
                if(buff[j++]=='$') cdollar++;
            }
            salt = (char *)malloc(sizeof(char));
            pass = (char *)malloc(sizeof(char));
            int saltlen = 0;
            int passlen = 0;
            while(buff[j]!='$') {
                salt[saltlen++] = buff[j++];
                salt = (char*)realloc(salt,sizeof(char)*(saltlen+1));
            }
            salt[saltlen] = '\0';
            j++;
            while(buff[j]!=':') {
                pass[passlen++] = buff[j++];
                pass = (char*)realloc(pass,sizeof(char)*(passlen+1));
            }
            pass[passlen] = '\0';
        }
        i++;
    }
    if(strlen(salt)==0 || strlen(pass)==0) return -1;
    *saltptr = salt;
    *passptr = pass;
    return 0;
}

void HMAC_sign(FILE* in, FILE* out, EVP_PKEY* pkey) {

    EVP_MD_CTX* ctx;
    char* sign; size_t siglen;

    ctx = EVP_MD_CTX_create();

    if(EVP_DigestInit_ex(ctx,EVP_get_digestbyname("SHA256"),NULL)!=1) {
        printf("EVP_DigestInit_ex Failed.\n");
        EVP_MD_CTX_destroy(ctx);
        abort();
    }

    if(EVP_DigestSignInit(ctx,NULL,EVP_get_digestbyname("SHA256"),NULL,pkey)!=1) {
        printf("EVP_DigestSignInit Failed.\n");
        EVP_MD_CTX_destroy(ctx);
        abort();
    }

    while(1) {
        char* inbuf=malloc(sizeof(char)*17);
        size_t inlen = fread(inbuf,1,16,in);

        if(inlen<=0) break;

        if(EVP_DigestSignUpdate(ctx,inbuf,inlen)!=1) {
            printf("EVP_DigestSignUpdate Failed.\n");
            EVP_MD_CTX_destroy(ctx);
            abort();
        }

        free(inbuf);
    }

    size_t len;
    if(EVP_DigestSignFinal(ctx, NULL, &len)!=1) {
        printf("EVP_DigestSignFinal(1) Failed.\n");
        EVP_MD_CTX_destroy(ctx);
        abort();
    }

    sign = (char*)malloc(sizeof(char)*len);
    siglen = len;

    if(EVP_DigestSignFinal(ctx, sign, &siglen)!=1) {
        printf("EVP_DigestSignFinal(2) Failed.\n");
        EVP_MD_CTX_destroy(ctx);
        abort();
    }

    fwrite(sign,1,siglen,out);

    EVP_MD_CTX_destroy(ctx);
    return;
}

int main(int argc, char *argv[])
{
    char* uname = malloc(0);    
    uname=getOwnerName(uname,argv[1]);
    char** saltptr=(char**)malloc(0);
    char** passptr=(char**)malloc(0);
    readShadow(uname,saltptr,passptr);

    EVP_PKEY *key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,NULL,*passptr,strlen(*passptr));

    char* filesign=argv[1];
    strcat(filesign,".sign");

    FILE* out = fopen(filesign,"wb");
    HMAC_sign(stdin,out,key);
    fclose(out);

    chmod(argv[1],0600);
    struct acl* meta = load_acl(argv[1]);
    meta->owner="r--";
    meta->onwer_group="---";
    meta->others = "---";
    meta->mask="";
    meta->named_groups="";
    meta->named_users="";
    save_acl(argv[1],meta);

    exit(EXIT_SUCCESS);
}
