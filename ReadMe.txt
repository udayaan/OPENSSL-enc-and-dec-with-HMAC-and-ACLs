Name : udayaan
Roll : 2017119

Info:
This system overides the DAC permission system with Access control lists.
The system uses the extended attributes of files and folders to store the access control lists.


Assumptions:
1. Only -m and -x options available for setacl.
2. in the -x option for setacl, the following commands types are allowed: 
    setacl -x u:name,g:name,m,d:u,d:g,d:m,d:o filename
3. The arguments are strictly follow the format:
    setacl -m u:name:rwx,u:name2:rw-,u::r-x filename
    and 
    setacl -x u:name,g:name filename

    No spaces in arguments.
4. permission in rwx format. example: 
    rw- is allowed as permission, not rw. 
    --- is allowed as permission not a blank.
5. in ls when no acl perm present, no permissions are shown. 
6. in ls, permissions shown in format : 
    rwxrwxrwxrwx

    first three bits for user, next three bits for group, next three bits for others and 
    last three bits for mask
7. maximum number of groups to which user belongs is 1000.
8. if acls are not set for a dir, then by default permissions to read is denied.
9. user can only use this system on files in which the owner has DAC permission to read and write.
10. expected complete path to files or programs.
11. create_dir takes full directory path as input.
12. only owner of file and fakeroot user can set acl entries of a file or directory with or without 
the write permission. No other user can modify the entries without write permission to that file.
13. user can add acl to any file. so user can set acl of an executable file.

Testing against Test Cases:
1. ./getacl.o testdir/
Current effective user id:0
#Owner:udayaan
#Group:udayaan
OWNER:rwx
NAMED_USERS:udayaan:rwx
OWNER_GROUP:rw-
NAMED_GROUPS:
MASK:rw-
OTHERS:rw-
DEFAULT_OWNER:rwx
DEFAULT_NAMED_USERS:
DEFAULT_OWNER_GROUP:r-x
DEFAULT_NAMED_GROUPS:
DEFAULT_MASK:
DEFAULT_OTHERS:r-x
Current effective user id:1000

2. ./setacl.o -m d:u::rwx testdir/
    ./getacl.o testdir/
Current effective user id:0
#Owner:udayaan
#Group:udayaan
OWNER:rwx
NAMED_USERS:udayaan:rwx
OWNER_GROUP:rw-
NAMED_GROUPS:
MASK:rw-
OTHERS:rw-
DEFAULT_OWNER:rw-
DEFAULT_NAMED_USERS:
DEFAULT_OWNER_GROUP:r-x
DEFAULT_NAMED_GROUPS:
DEFAULT_MASK:
DEFAULT_OTHERS:r-x
Current effective user id:1000

3. 
owner:udayaan  group:udayaan 23   xyv   file
/home/udayaan/Desktop/SE_Proj2/testdir//xyv: permissions: rwxr-xr-x

./getacl.o testdir/xyv
Current effective user id:0
#Owner:udayaan
#Group:udayaan
OWNER:rwx
NAMED_USERS:
OWNER_GROUP:r--
NAMED_GROUPS:
MASK:
OTHERS:r--
Current effective user id:1000

fake@udayaan-VirtualBox:/home/udayaan/Desktop/SE_Proj2$ ./fput.o /home/udayaan/Desktop/SE_Proj2/testdir/xyv 
Current effective user id:0
sjdidckjdsi
Permission denied.


Defense:
1. All the files created  y fput have only read write permissions to the owner.
So, no other person except root can modify his or her file using DAC permissions.

2. All the directories created by create_dir have only read write permissions to the owner.
So, no other person except root can modify the directory using DAC permissions.

3. After successful execution of the program, the root priviledges are revoked using setuid in the 
program. 
