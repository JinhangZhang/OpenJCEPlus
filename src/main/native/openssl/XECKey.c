/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h"
#include "Utils.h"

/* Ordinals from CurveUtil.CURVE, not OpenSSL NIDs. */
static const char *curveName(jint option) {
    switch (option) {
        case 0: return "X25519";
        case 1: return "X448";
        default: return NULL;
    }
}

static size_t keySize(EVP_PKEY *key) {
    if (key != NULL && EVP_PKEY_is_a(key, "X25519")) return 32;
    if (key != NULL && EVP_PKEY_is_a(key, "X448")) return 56;
    return 0;
}

static int writePublicKey(JNIEnv *env, EVP_PKEY *key, jlong bufferPtr) {
    size_t expected = keySize(key), size = expected;
    if (!bufferPtr || !expected ||
        EVP_PKEY_get_raw_public_key(
            key, (unsigned char *)(intptr_t)bufferPtr, &size) != 1 ||
        size != expected) {
        throwOSSLException(env, 0, "XDH: failed to export raw public key");
        return 0;
    }
    return 1;
}

JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1generate(
    JNIEnv *env, jclass clazz, jlong contextId, jint option, jlong bufferPtr) {
    const char *name = curveName(option);
    EVP_PKEY *key = NULL;

    /*
     * Like Digest.c, use the default OpenSSL libctx. contextId is currently
     * a placeholder, NOT an OSSL_LIB_CTX pointer.
     */
    if (name == NULL || bufferPtr == 0) {
        throwOSSLException(env, 0, "XDH: unsupported curve or null output buffer");
        return 0;
    }

    key = EVP_PKEY_Q_keygen(NULL, NULL, name);
    if (key == NULL) {
        throwOSSLException(env, 0, "XDH: key generation failed");
        return 0;
    }

    if (!writePublicKey(env, key, bufferPtr)) {
        EVP_PKEY_free(key);
        return 0;
    }

    return (jlong)(intptr_t)key;
}

/* Import PKCS#8 or SPKI without entering a JNI critical region. */
static EVP_PKEY *importKey(JNIEnv *env, jbyteArray encoded, int privateKey) {
    unsigned char *bytes = NULL;
    const unsigned char *cursor;
    EVP_PKEY *key = NULL;
    PKCS8_PRIV_KEY_INFO *info = NULL;
    jsize size;

    if (encoded == NULL || (size = (*env)->GetArrayLength(env, encoded)) == 0) {
        throwOSSLException(env, 0, "XDH: empty key encoding");
        return NULL;
    }

    bytes = OPENSSL_malloc((size_t)size);
    if (bytes == NULL) {
        throwOSSLException(env, 0, "XDH: key allocation failed");
        return NULL;
    }

    (*env)->GetByteArrayRegion(env, encoded, 0, size, (jbyte *)bytes);
    if ((*env)->ExceptionCheck(env)) goto cleanup;

    cursor = bytes;
    if (privateKey) {
        info = d2i_PKCS8_PRIV_KEY_INFO(NULL, &cursor, size);
        if (info != NULL) {
            key = EVP_PKCS82PKEY_ex(info, NULL, NULL);
        }
    } else {
        key = d2i_PUBKEY_ex(NULL, &cursor, size, NULL, NULL);
    }

    if (keySize(key) == 0 || cursor != bytes + size) {
        EVP_PKEY_free(key);
        key = NULL;
        throwOSSLException(env, 0, "XDH: invalid key encoding or key type");
    }

cleanup:
    PKCS8_PRIV_KEY_INFO_free(info);
    OPENSSL_clear_free(bytes, (size_t)size);
    return key;
}

JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1createPrivateKey(
    JNIEnv *env, jclass clazz, jlong contextId,
    jbyteArray encoded, jlong bufferPtr) {
    EVP_PKEY *key;

    if (bufferPtr == 0) {
        throwOSSLException(env, 0, "XDH: null public key buffer");
        return 0;
    }

    key = importKey(env, encoded, 1);
    if (key != NULL && !writePublicKey(env, key, bufferPtr)) {
        EVP_PKEY_free(key);
        key = NULL;
    }

    return (jlong)(intptr_t)key;
}

JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1createPublicKey(
    JNIEnv *env, jclass clazz, jlong contextId, jbyteArray encoded) {
    return (jlong)(intptr_t)importKey(env, encoded, 0);
}

JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1getPrivateKeyBytes(
    JNIEnv *env, jclass clazz, jlong contextId, jlong keyId) {
    EVP_PKEY *key = (EVP_PKEY *)(intptr_t)keyId;
    PKCS8_PRIV_KEY_INFO *info = NULL;
    unsigned char *encoded = NULL;
    jbyteArray result = NULL;
    int size = 0;

    if (keySize(key) == 0 || (info = EVP_PKEY2PKCS8(key)) == NULL ||
        (size = i2d_PKCS8_PRIV_KEY_INFO(info, &encoded)) <= 0) {
        throwOSSLException(env, 0, "XDH: private key encoding failed");
        goto cleanup;
    }

    result = (*env)->NewByteArray(env, size);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(
            env, result, 0, size, (jbyte *)encoded);
    }

cleanup:
    OPENSSL_clear_free(encoded, size > 0 ? (size_t)size : 0);
    PKCS8_PRIV_KEY_INFO_free(info);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1getPublicKeyBytes(
    JNIEnv *env, jclass clazz, jlong contextId, jlong keyId) {
    unsigned char bytes[56];
    EVP_PKEY *key = (EVP_PKEY *)(intptr_t)keyId;
    size_t size = keySize(key);
    jbyteArray result;

    if (!size || EVP_PKEY_get_raw_public_key(key, bytes, &size) != 1) {
        throwOSSLException(env, 0, "XDH: public key export failed");
        return NULL;
    }

    result = (*env)->NewByteArray(env, (jsize)size);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(
            env, result, 0, (jsize)size, (jbyte *)bytes);
    }
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1computeECDHSecret(
    JNIEnv *env, jclass clazz, jlong contextId,
    jlong genCtx, jlong pubId, jlong privId) {
    EVP_PKEY *publicKey = (EVP_PKEY *)(intptr_t)pubId;
    EVP_PKEY *privateKey = (EVP_PKEY *)(intptr_t)privId;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char secret[56] = {0};
    unsigned char nonzero = 0;
    size_t expected = keySize(privateKey), size = sizeof(secret), i;
    jbyteArray result = NULL;

    if (!expected || keySize(publicKey) != expected) {
        throwOSSLException(env, 0, "XDH: incompatible keys");
        goto cleanup;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, privateKey, NULL);
    if (ctx == NULL || EVP_PKEY_derive_init(ctx) != 1 ||
        EVP_PKEY_derive_set_peer(ctx, publicKey) != 1 ||
        EVP_PKEY_derive(ctx, secret, &size) != 1 || size != expected) {
        throwOSSLException(env, 0, "XDH: key agreement failed");
        goto cleanup;
    }

    for (i = 0; i < size; i++) {
        nonzero |= secret[i];
    }
    if (!nonzero) {
        throwOSSLException(env, 0, "XDH: all-zero shared secret");
        goto cleanup;
    }

    result = (*env)->NewByteArray(env, (jsize)size);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(
            env, result, 0, (jsize)size, (jbyte *)secret);
    }

cleanup:
    OPENSSL_cleanse(secret, sizeof(secret));
    EVP_PKEY_CTX_free(ctx);
    return result;
}

JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1delete(
    JNIEnv *env, jclass clazz, jlong contextId, jlong keyId) {
    EVP_PKEY_free((EVP_PKEY *)(intptr_t)keyId);
}
