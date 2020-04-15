#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#define KEYLEN 16

char* substring(char* target, char* string, int start, int end) {
    int j = 0;
    for(int i=start;i<end;++i)  {
        target[j] = string[i];
        j+=1;
    }
    target[j] = '\0';
    return target;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
//             unsigned char *iv, unsigned char *ciphertext)
// {
//     EVP_CIPHER_CTX *ctx;

//     int len;

//     int ciphertext_len;

//     /* Create and initialise the context */
//     if(!(ctx = EVP_CIPHER_CTX_new()))
//         handleErrors();

//     /*
//      * Initialise the encryption operation. IMPORTANT - ensure you use a key
//      * and IV size appropriate for your cipher
//      * In this example we are using 256 bit AES (i.e. a 256 bit key). The
//      * IV size for *most* modes is the same as the block size. For AES this
//      * is 128 bits
//      */
//     if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
//         handleErrors();

//     /*
//      * Provide the message to be encrypted, and obtain the encrypted output.
//      * EVP_EncryptUpdate can be called multiple times if necessary
//      */
//     if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
//         handleErrors();
//     ciphertext_len = len;

//     /*
//      * Finalise the encryption. Further ciphertext bytes may be written at
//      * this stage.
//      */
//     if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
//         handleErrors();
//     ciphertext_len += len;

//     /* Clean up */
//     EVP_CIPHER_CTX_free(ctx);

//     return ciphertext_len;
// }

// int encrypt(char * plaintext,char* ciphertext, char* key, char* iv) {
    
//     EVP_CIPHER_CTX* ctx;
//     if(!(ctx=EVP_CIPHER_CTX_new())) {
//         ERR_print_errors_fp(stderr);
//         abort();    
//     }

//     if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)!=1) {
//         ERR_print_errors_fp(stderr);
//         abort();
//     }

//     int cipherlen;

//     if(EVP_EncryptUpdate(ctx, ciphertext, &cipherlen, plaintext, strlen(plaintext))!=1) {
//         ERR_print_errors_fp(stderr);
//         abort();
//     }

//     int len;

//     if(EVP_EncryptFinal_ex(ctx, ciphertext + cipherlen, &len)!=1) {
//         ERR_print_errors_fp(stderr);
//         abort();   
//     }
//     cipherlen += len;

//     EVP_CIPHER_CTX_free(ctx);

//     return cipherlen;
// }

// int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
//             unsigned char *iv, unsigned char *plaintext)
// {
//     EVP_CIPHER_CTX *ctx;

//     int len;

//     int plaintext_len;

//     /* Create and initialise the context */
//     if(!(ctx = EVP_CIPHER_CTX_new()))
//         handleErrors();

//     /*
//      * Initialise the decryption operation. IMPORTANT - ensure you use a key
//      * and IV size appropriate for your cipher
//      * In this example we are using 256 bit AES (i.e. a 256 bit key). The
//      * IV size for *most* modes is the same as the block size. For AES this
//      * is 128 bits
//      */
//     if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
//         handleErrors();

//     /*
//      * Provide the message to be decrypted, and obtain the plaintext output.
//      * EVP_DecryptUpdate can be called multiple times if necessary.
//      */
//     if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
//         handleErrors();
//     plaintext_len = len;

//     /*
//      * Finalise the decryption. Further plaintext bytes may be written at
//      * this stage.
//      */
//     if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
//         handleErrors();
//     plaintext_len += len;

//     /* Clean up */
//     EVP_CIPHER_CTX_free(ctx);

//     return plaintext_len;
// }

// int decrypt(char* ciphertext, int cipherlen, char* plaintext, char* key, char* iv) {

//     EVP_CIPHER_CTX *ctx;
//     if(!(ctx=EVP_CIPHER_CTX_new())) {
//         ERR_print_errors_fp(stderr);
//         abort();    
//     }

//     if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)!=1) {
//         ERR_print_errors_fp(stderr);
//         abort();
//     }

//     int plaintextlen;

//     if(EVP_DecryptUpdate(ctx, plaintext, &plaintextlen, ciphertext, cipherlen)!=1) {
//         ERR_print_errors_fp(stderr);
//         abort();
//     }

//     printf("!!!%d\n",plaintextlen);

//     int len;

//     if(EVP_DecryptFinal_ex(ctx, plaintext + plaintextlen, &len)!=1) {
//         ERR_print_errors_fp(stderr);
//         abort();
//     }
//     plaintextlen += len;

//     EVP_CIPHER_CTX_free(ctx);
    
//     return plaintextlen;
// }

// int decrypt2(char* ciphertext, int cipherlen, char* plaintext, char* key, char* iv) {
    
//     int padlen;
//     int plaintextlen=0;
//     EVP_CIPHER_CTX *ctx;
    
//     if(!(ctx=EVP_CIPHER_CTX_new())) {
//         ERR_print_errors_fp(stderr);
//         abort();    
//     }

//     if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)!=1) {
//         ERR_print_errors_fp(stderr);
//         abort();
//     }

    
//     if(EVP_DecryptUpdate(ctx, plaintext+plaintextlen, &padlen, ciphertext, cipherlen)!=1) {
//         ERR_print_errors_fp(stderr);
//         abort();
//     }
//     plaintextlen+=padlen;


//     printf("plaintextlen : %d\n",plaintextlen);
//     printf("plaintext : %s\n",plaintext);
    
//     if(EVP_DecryptFinal_ex(ctx, plaintext + plaintextlen, &padlen)!=1) {
//         ERR_print_errors_fp(stderr);
//         abort();
//     }
//     plaintextlen+=padlen;
    
//     EVP_CIPHER_CTX_free(ctx);
    
//     return plaintextlen;
// }

// int EVPCipher(char* in, int inlen, char* out, char* key, char* iv, int encflag) {
//     int len;
//     int outlen=0;
//     EVP_CIPHER_CTX *ctx;
    
//     if(!(ctx=EVP_CIPHER_CTX_new())) {
//         ERR_print_errors_fp(stderr);
//         abort();    
//     }

//     if(EVP_CipherInit_ex(ctx,EVP_aes_256_cbc(),NULL,key,iv,encflag)!=1) {
//         ERR_print_errors_fp(stderr);
//         abort();
//     }

//     if(EVP_CipherUpdate(ctx,out,&len,in,inlen)!=1) {
//         ERR_print_errors_fp(stderr);
//         abort();
//     }
//     outlen = len;

//     if(EVP_CipherFinal_ex(ctx,out+outlen,&len)!=1) {
//         ERR_print_errors_fp(stderr);
//         abort();
//     }
//     outlen+=len;

//     EVP_CIPHER_CTX_free(ctx);
    
//     return outlen;
// }


int do_crypt(FILE *in, FILE *out, char* key, char* iv, int do_encrypt)
{
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1024], outbuf[1024 + EVP_CIPHER_block_size(EVP_aes_128_cbc())];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;
    

    /* Don't set key or IV right away; we want to check lengths */
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    /* Now we can set key and IV */
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    while(1)
    {
        inlen = fread(inbuf, 1, 1024, in);
        if(inlen <=0) break;
        if(!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen))
        {
            /* Error */
            EVP_CIPHER_CTX_free(ctx);
            abort();
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if(!EVP_CipherFinal_ex(ctx, outbuf, &outlen))
    {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        abort();
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}


int main(int argc, char const *argv[])
{
    char pass[] = "ArXEtYg2JEVN25dO/MeXIm9033/47P.aARi74z7Ftv1k7Nek5TGwzNaZbtTF5aLyOjoso4jg3UKs.lPlXAdg1.";
    char salt[] = "IHWXhp1J";

    // char* out = (char*)malloc(sizeof(char)*KEYLEN);
    // PKCS5_PBKDF2_HMAC_SHA1(pass,strlen(pass),salt,strlen(salt),1000,KEYLEN,out);
    // for(int i=0;i<KEYLEN;i++) { printf("%02x", out[i]); } printf("\n");

    char*key = (char*)malloc(sizeof(char)*17);
    // substring(key,out,0,8);
    char* iv = (char*)malloc(sizeof(char)*17);
    // substring(iv,out,8,16);

    EVP_BytesToKey(EVP_aes_128_cbc(),EVP_sha1(),salt,pass,strlen(pass),1000,key,iv);

    for(int i=0;i<16;i++) { printf("%02x", key[i]); } printf("\n");
    for(int i=0;i<16;i++) { printf("%02x", iv[i]); } printf("\n");

    printf("YES\n");
    
    unsigned char plaintext[] =
        "The fread() function in C++ reads the block of data from stream. This function first, reads count number of objects, each one with a size of size bytes from the given input stream. The total amount of bytes read, if successful is ( size*count ). According to the no. of characters read, the indicator file position is incremented. If the objects read are not trivially copy-able, then the behavior is undefined and if the value of size or count is equal to zero, then this program will simply return 0.1010101010";
    
    printf("%ld\n",strlen(plaintext));
    // unsigned char ciphertext[1000];

    
    // unsigned char decryptedtext[1000];

    // int decryptedtext_len, ciphertext_len;

    
    // ciphertext_len = EVPCipher(plaintext,strlen(plaintext),ciphertext,key,iv,1);

    // printf("%d\n",ciphertext_len);
    // /* Do something useful with the ciphertext here */
    // printf("Ciphertext is:\n");
    // // printf("%s\n",ciphertext);
    // BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    // /* Decrypt the ciphertext */
    // decryptedtext_len = EVPCipher(ciphertext,ciphertext_len,decryptedtext,key,iv,0);

    // /* Add a NULL terminator. We are expecting printable text */
    // decryptedtext[decryptedtext_len] = '\0';

    // /* Show the decrypted text */
    // printf("Decrypted text is:\n");
    // printf("%s\n", decryptedtext);

    return 0;
}   
