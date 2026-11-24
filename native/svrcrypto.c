/*
 * Copyright (c) 2015 128 Technology, Inc.
 * Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
 *
 * This code is licensed under the MIT license.
 */

#include <gcrypt.h>
#include <lua.h>
#include <lauxlib.h>

#include <stdint.h>
#include <stdlib.h>

#define MAX_CRYPTO_INPUT (16U * 1024U * 1024U)

static int
push_error(lua_State *state, const char *message)
{
    lua_pushnil(state);
    lua_pushstring(state, message);
    return 2;
}

static int
key_length_to_algorithm(size_t key_length)
{
    if (key_length == 16)
    {
        return GCRY_CIPHER_AES128;
    }
    if (key_length == 32)
    {
        return GCRY_CIPHER_AES256;
    }
    return 0;
}

static int
decrypt_cbc(lua_State *state)
{
    size_t key_length;
    size_t iv_length;
    size_t input_length;
    const char *key = luaL_checklstring(state, 1, &key_length);
    const char *iv = luaL_checklstring(state, 2, &iv_length);
    const char *input = luaL_checklstring(state, 3, &input_length);
    const int algorithm = key_length_to_algorithm(key_length);
    gcry_cipher_hd_t cipher = NULL;
    gcry_error_t error;
    char *output;

    if (algorithm == 0)
    {
        return push_error(state, "AES key must be 16 or 32 bytes");
    }
    if (iv_length != 16)
    {
        return push_error(state, "AES-CBC IV must be 16 bytes");
    }
    if (input_length > MAX_CRYPTO_INPUT)
    {
        return push_error(state, "AES-CBC input exceeds size limit");
    }
    if (input_length == 0 || input_length % 16 != 0)
    {
        return push_error(state, "AES-CBC input must be a non-empty block multiple");
    }

    error = gcry_cipher_open(&cipher, algorithm, GCRY_CIPHER_MODE_CBC, 0);
    if (error == 0)
    {
        error = gcry_cipher_setkey(cipher, key, key_length);
    }
    if (error == 0)
    {
        error = gcry_cipher_setiv(cipher, iv, iv_length);
    }
    if (error != 0)
    {
        if (cipher != NULL)
        {
            gcry_cipher_close(cipher);
        }
        return push_error(state, "Unable to initialize AES-CBC");
    }

    output = (char *)malloc(input_length);
    if (output == NULL)
    {
        gcry_cipher_close(cipher);
        return push_error(state, "Unable to allocate AES-CBC output");
    }
    error = gcry_cipher_decrypt(cipher, output, input_length, input, input_length);
    gcry_cipher_close(cipher);
    if (error != 0)
    {
        free(output);
        return push_error(state, "AES-CBC decryption failed");
    }

    lua_pushlstring(state, output, input_length);
    free(output);
    return 1;
}

static int
decrypt_gcm(lua_State *state)
{
    size_t key_length;
    size_t nonce_length;
    size_t input_length;
    size_t tag_length;
    size_t aad_length;
    const char *key = luaL_checklstring(state, 1, &key_length);
    const char *nonce = luaL_checklstring(state, 2, &nonce_length);
    const char *input = luaL_checklstring(state, 3, &input_length);
    const char *tag = luaL_checklstring(state, 4, &tag_length);
    const char *aad = luaL_optlstring(state, 5, "", &aad_length);
    const int algorithm = key_length_to_algorithm(key_length);
    gcry_cipher_hd_t cipher = NULL;
    gcry_error_t error;
    char *output;

    if (algorithm == 0)
    {
        return push_error(state, "AES key must be 16 or 32 bytes");
    }
    if (nonce_length != 12 || tag_length != 16)
    {
        return push_error(state, "AES-GCM nonce/tag lengths must be 12/16 bytes");
    }
    if (input_length > MAX_CRYPTO_INPUT || aad_length > MAX_CRYPTO_INPUT)
    {
        return push_error(state, "AES-GCM input exceeds size limit");
    }

    error = gcry_cipher_open(&cipher, algorithm, GCRY_CIPHER_MODE_GCM, 0);
    if (error == 0)
    {
        error = gcry_cipher_setkey(cipher, key, key_length);
    }
    if (error == 0)
    {
        error = gcry_cipher_setiv(cipher, nonce, nonce_length);
    }
    if (error == 0 && aad_length != 0)
    {
        error = gcry_cipher_authenticate(cipher, aad, aad_length);
    }
    if (error != 0)
    {
        if (cipher != NULL)
        {
            gcry_cipher_close(cipher);
        }
        return push_error(state, "Unable to initialize AES-GCM");
    }

    output = (char *)malloc(input_length == 0 ? 1 : input_length);
    if (output == NULL)
    {
        gcry_cipher_close(cipher);
        return push_error(state, "Unable to allocate AES-GCM output");
    }

    error = gcry_cipher_decrypt(cipher, output, input_length, input, input_length);
    if (error == 0)
    {
        error = gcry_cipher_checktag(cipher, tag, tag_length);
    }
    gcry_cipher_close(cipher);
    if (error != 0)
    {
        free(output);
        return push_error(state, "AES-GCM authentication failed");
    }

    lua_pushlstring(state, output, input_length);
    free(output);
    return 1;
}

static const luaL_Reg methods[] = {
    {"decrypt_cbc", decrypt_cbc},
    {"decrypt_gcm", decrypt_gcm},
    {NULL, NULL},
};

int
luaopen_svrcrypto(lua_State *state)
{
    if (gcry_check_version(NULL) == NULL)
    {
        return luaL_error(state, "libgcrypt initialization failed");
    }
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    luaL_checkversion(state);
    luaL_newlib(state, methods);
    return 1;
}
