/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2016  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <linux/keyctl.h>
#include <errno.h>

#include "private.h"
#include "util.h"
#include "key.h"
#include "string.h"
#include "random.h"

#ifndef KEYCTL_DH_COMPUTE
#define KEYCTL_DH_COMPUTE 23

struct keyctl_dh_params {
	int32_t private;
	int32_t prime;
	int32_t base;
};
#endif

#ifndef KEYCTL_PKEY_QUERY
#define KEYCTL_PKEY_QUERY	24
#define KEYCTL_PKEY_ENCRYPT	25
#define KEYCTL_PKEY_DECRYPT	26
#define KEYCTL_PKEY_SIGN	27
#define KEYCTL_PKEY_VERIFY	28

#define KEYCTL_SUPPORTS_ENCRYPT	0x01
#define KEYCTL_SUPPORTS_DECRYPT	0x02
#define KEYCTL_SUPPORTS_SIGN	0x04
#define KEYCTL_SUPPORTS_VERIFY	0x08

struct keyctl_pkey_query {
	uint32_t supported_ops;
	uint32_t key_size;
	uint16_t max_data_size;
	uint16_t max_sig_size;
	uint16_t max_enc_size;
	uint16_t max_dec_size;

	uint32_t __spare[10];
};

struct keyctl_pkey_params {
	int32_t key_id;
	uint32_t in_len;
	union {
		uint32_t out_len;
		uint32_t in2_len;
	};
	uint32_t __spare[7];
};
#endif

static int32_t internal_keyring;

struct l_key {
	int type;
	int32_t serial;
};

struct l_keyring {
	int type;
	int32_t serial;
};

static const char * const key_type_names[] = {
	[L_KEY_RAW] = "user",
	[L_KEY_RSA] = "asymmetric",
};

static long kernel_add_key(const char *type, const char *description,
				const void *payload, size_t len, int32_t keyring)
{
	long result;

	result = syscall(__NR_add_key, type, description, payload, len,
				keyring);

	return result >= 0 ? result : -errno;
}

static long kernel_read_key(int32_t serial, const void *payload, size_t len)
{
	long result;

	result = syscall(__NR_keyctl, KEYCTL_READ, serial, payload, len);

	return result >= 0 ? result : -errno;
}

static long kernel_update_key(int32_t serial, const void *payload, size_t len)
{
	long result;

	result = syscall(__NR_keyctl, KEYCTL_UPDATE, serial, payload, len);

	return result >= 0 ? result : -errno;
}

static long kernel_revoke_key(int32_t serial)
{
	long result;

	result = syscall(__NR_keyctl, KEYCTL_REVOKE, serial);

	return result >= 0 ? result : -errno;
}

static long kernel_link_key(int32_t key_serial, int32_t ring_serial)
{
	long result;

	result = syscall(__NR_keyctl, KEYCTL_LINK, key_serial, ring_serial);

	return result >= 0 ? result : -errno;
}

static long kernel_unlink_key(int32_t key_serial, int32_t ring_serial)
{
	long result;

	result = syscall(__NR_keyctl, KEYCTL_UNLINK, key_serial, ring_serial);

	return result >= 0 ? result : -errno;
}

static char *format_key_info(const char *encoding, const char *hash)
{
	struct l_string *info;

	if (!encoding && !hash)
		return NULL;

	info = l_string_new(0);

	if (encoding)
		l_string_append_printf(info, "enc=%s ", encoding);

	if (hash)
		l_string_append_printf(info, "hash=%s", hash);

	return l_string_free(info, false);
}

static long kernel_query_key(int32_t key_serial, const char *encoding,
				const char *hash, size_t *size, bool *public)
{
	long result;
	struct keyctl_pkey_query query;
	char *info = format_key_info(encoding, hash);

	memset(&query, 0, sizeof(query));

	result = syscall(__NR_keyctl, KEYCTL_PKEY_QUERY, key_serial, 0,
				info ?: "", &query);
	if (result == 0) {
		*size = query.key_size;
		*public = ((query.supported_ops & KEYCTL_SUPPORTS_ENCRYPT) &&
			!(query.supported_ops & KEYCTL_SUPPORTS_DECRYPT));
	}
	l_free(info);

	return result >= 0 ? result : -errno;
}

static long kernel_dh_compute(int32_t private, int32_t prime, int32_t base,
			      void *payload, size_t len)
{
	long result;

	struct keyctl_dh_params params = { .private = private,
					   .prime = prime,
					   .base = base };

	result = syscall(__NR_keyctl, KEYCTL_DH_COMPUTE, &params, payload, len,
			NULL);

	return result >= 0 ? result : -errno;
}

static long kernel_key_eds(int op, int32_t serial, const char *encoding,
				const char *hash, const void *in, void *out,
				size_t len_in, size_t len_out)
{
	long result;
	struct keyctl_pkey_params params = { .key_id = serial,
					     .in_len = len_in,
					     .out_len = len_out };
	char *info = format_key_info(encoding, hash);

	result = syscall(__NR_keyctl, op, &params, info ?: "", in, out);
	l_free(info);

	return result >= 0 ? result : -errno;
}

static bool setup_internal_keyring(void)
{
	internal_keyring = kernel_add_key("keyring", "ell-internal", NULL, 0,
						KEY_SPEC_THREAD_KEYRING);

	if (internal_keyring <= 0) {
		internal_keyring = 0;
		return false;
	}

	return true;
}

LIB_EXPORT struct l_key *l_key_new(enum l_key_type type, const void *payload,
					size_t payload_length)
{
	struct l_key *key;
	char *description;

	if (unlikely(!payload))
		return NULL;

	if (unlikely((size_t)type >= L_ARRAY_SIZE(key_type_names)))
		return NULL;

	if (!internal_keyring && !setup_internal_keyring())
		return NULL;

	key = l_new(struct l_key, 1);
	key->type = type;
	description = l_strdup_printf("ell-key-%p", key);
	key->serial = kernel_add_key(key_type_names[type], description, payload,
					payload_length, internal_keyring);
	l_free(description);

	if (key->serial < 0) {
		l_free(key);
		key = NULL;
	}

	/*
	 * TODO: Query asymmetric key algorithm from the kernel and
	 * ensure that it matches the expected l_key_type. This can
	 * currently be found by digging through /proc/keys, but a
	 * keyctl() op makes more sense.
	 */

	return key;
}

LIB_EXPORT void l_key_free(struct l_key *key)
{
	if (unlikely(!key))
		return;

	kernel_revoke_key(key->serial);

	l_free(key);
}

LIB_EXPORT bool l_key_update(struct l_key *key, const void *payload, size_t len)
{
	long error;

	if (unlikely(!key))
		return false;

	error = kernel_update_key(key->serial, payload, len);

	return error == 0;
}

LIB_EXPORT bool l_key_extract(struct l_key *key, void *payload, size_t *len)
{
	long keylen;

	if (unlikely(!key))
		return false;

	keylen = kernel_read_key(key->serial, payload, *len);

	if (keylen < 0 || (size_t)keylen > *len) {
		memset(payload, 0, *len);
		return false;
	}

	*len = keylen;
	return true;
}

LIB_EXPORT ssize_t l_key_get_payload_size(struct l_key *key)
{
	return kernel_read_key(key->serial, NULL, 0);
}

static const char *lookup_cipher(enum l_key_cipher_type cipher)
{
	const char* ret = NULL;

	switch (cipher) {
	case L_KEY_RSA_PKCS1_V1_5:
		/* Padding is handled in userspace, so the kernel only sees
		 * raw RSA operations
		 */
		ret = "raw";
		break;
	case L_KEY_RSA_RAW:
		ret = "raw";
		break;
	}

	return ret;
}

static const char *lookup_checksum(enum l_checksum_type checksum)
{
	const char* ret = NULL;

	switch (checksum) {
	case L_CHECKSUM_NONE:
		break;
	case L_CHECKSUM_MD5:
		ret = "md5";
		break;
	case L_CHECKSUM_SHA1:
		ret = "sha1";
		break;
	case L_CHECKSUM_SHA256:
		ret = "sha256";
		break;
	case L_CHECKSUM_SHA384:
		ret = "sha384";
		break;
	case L_CHECKSUM_SHA512:
		ret = "sha512";
		break;
	}

	return ret;
}

bool l_key_get_info(struct l_key *key, enum l_key_cipher_type cipher,
			enum l_checksum_type checksum, size_t *bits,
			bool *public)
{
	if (unlikely(!key))
		return false;

	return !kernel_query_key(key->serial, lookup_cipher(cipher),
					lookup_checksum(checksum), bits,
					public);
}

static bool compute_common(struct l_key *base,
			   struct l_key *private,
			   struct l_key *prime,
			   void *payload, size_t *len)
{
	long result_len;
	bool usable_payload = *len != 0;

	result_len = kernel_dh_compute(private->serial, prime->serial,
				       base->serial, payload, *len);

	if (result_len > 0) {
		*len = result_len;
		return usable_payload;
	} else {
		return false;
	}
}

LIB_EXPORT bool l_key_compute_dh_public(struct l_key *generator,
					struct l_key *private,
					struct l_key *prime,
					void *payload, size_t *len)
{
	return compute_common(generator, private, prime, payload, len);
}

LIB_EXPORT bool l_key_compute_dh_secret(struct l_key *other_public,
					struct l_key *private,
					struct l_key *prime,
					void *payload, size_t *len)
{
	return compute_common(other_public, private, prime, payload, len);
}

/* Common code for encrypt/decrypt/sign */
static ssize_t eds_common(struct l_key *key,
				enum l_key_cipher_type cipher,
				enum l_checksum_type checksum, const void *in,
				void *out, size_t len_in, size_t len_out,
				int op)
{
	if (unlikely(!key))
		return -EINVAL;

	return kernel_key_eds(op, key->serial, lookup_cipher(cipher),
				lookup_checksum(checksum), in, out, len_in,
				len_out);
}

static void getrandom_nonzero(uint8_t *buf, int len)
{
	l_getrandom(buf, len);

	while (len--) {
		while (buf[0] == 0)
			l_getrandom(buf, 1);

		buf++;
	}
}

/* PKCS#1 v1.5 RSA padding according to RFC3447 */
static uint8_t *pad(const uint8_t *in, size_t len_in, size_t len_out,
			uint8_t flag, bool randfill)
{
	size_t fill_len;
	uint8_t *padded;

	if (len_in > len_out - 11)
		return NULL;

	padded = l_malloc(len_out);
	fill_len = len_out - len_in - 3;

	padded[0] = 0x00;
	padded[1] = flag;

	if (randfill)
		getrandom_nonzero(padded + 2, fill_len);
	else
		memset(padded + 2, 0xff, fill_len);

	padded[fill_len + 2] = 0x00;
	memcpy(padded + fill_len + 3, in, len_in);

	return padded;
}

static ssize_t unpad(uint8_t *in, uint8_t *out, size_t len_in, size_t len_out,
			uint8_t flag, bool randfill)
{
	size_t pos;
	ssize_t unpad_len;

	if (in[0] != 0x00 || in[1] != flag)
		return -EINVAL;

	if (randfill)
		for (pos = 2; pos < len_in && in[pos] != 0x00; pos++);
	else
		for (pos = 2; pos < len_in && in[pos] == 0xff; pos++);

	if (pos < 10 || pos == len_in)
		return -EINVAL;

	pos++;
	unpad_len = len_in - pos;

	if (out) {
		if ((size_t)unpad_len > len_out)
			return -EINVAL;

		memcpy(out, in + pos, unpad_len);
	}

	return unpad_len;
}

LIB_EXPORT ssize_t l_key_encrypt(struct l_key *key,
					enum l_key_cipher_type cipher,
					enum l_checksum_type checksum,
					const void *in, void *out,
					size_t len_in, size_t len_out)
{
	uint8_t *padded = NULL;
	ssize_t ret_len;

	if (cipher == L_KEY_RSA_PKCS1_V1_5) {
		padded = pad(in, len_in, len_out, 0x02, true);
		if (!padded)
			return -EOVERFLOW;

		cipher = L_KEY_RSA_RAW;
	}

	ret_len = eds_common(key, cipher, checksum, padded ?: in, out,
				padded ? len_out : len_in, len_out,
				KEYCTL_PKEY_ENCRYPT);

	l_free(padded);

	return ret_len;
}

LIB_EXPORT ssize_t l_key_decrypt(struct l_key *key,
					enum l_key_cipher_type cipher,
					enum l_checksum_type checksum,
					const void *in, void *out,
					size_t len_in, size_t len_out)
{
	uint8_t *padded = NULL;
	ssize_t ret_len;

	if (cipher == L_KEY_RSA_PKCS1_V1_5)
		padded = l_malloc(len_in);

	ret_len = eds_common(key, cipher, checksum, in, padded ?: out, len_in,
				padded ? len_in : len_out, KEYCTL_PKEY_DECRYPT);

	if (ret_len < 0)
		goto done;

	if (padded)
		ret_len = unpad(padded, out, ret_len, len_out, 0x02, true);

done:
	l_free(padded);

	return ret_len;
}

LIB_EXPORT ssize_t l_key_sign(struct l_key *key,
				enum l_key_cipher_type cipher,
				enum l_checksum_type checksum, const void *in,
				void *out, size_t len_in, size_t len_out)
{
	uint8_t *padded = NULL;
	ssize_t ret_len;

	if (cipher == L_KEY_RSA_PKCS1_V1_5) {
		padded = pad(in, len_in, len_out, 0x01, false);
		if (!padded)
			return -EOVERFLOW;

		cipher = L_KEY_RSA_RAW;
	}

	ret_len = eds_common(key, cipher, checksum, padded ?: in, out,
				padded ? len_out : len_in, len_out,
				KEYCTL_PKEY_SIGN);

	l_free(padded);

	return ret_len;
}

LIB_EXPORT bool l_key_verify(struct l_key *key,
				enum l_key_cipher_type cipher,
				enum l_checksum_type checksum, const void *data,
				const void *sig, size_t len_data,
				size_t len_sig)
{
	enum l_key_cipher_type kernel_cipher;
	ssize_t hash_len;
	uint8_t *compare_hash;
	bool success = false;
	uint8_t *sig_hash = l_malloc(len_sig);

	/* The keyctl verify implementation compares the verify results
	 * before we get a chance to unpad it. Instead, use the *encrypt*
	 * operation (which uses the same math as verify) to get the hash
	 * returned to us so it can be unpadded before comparing
	 */
	if (cipher == L_KEY_RSA_PKCS1_V1_5)
		kernel_cipher = L_KEY_RSA_RAW;
	else
		kernel_cipher = cipher;

	hash_len = eds_common(key, kernel_cipher, checksum, sig, sig_hash,
				len_sig, len_sig, KEYCTL_PKEY_ENCRYPT);

	if (hash_len < 0) {
		success = false;
		goto done;
	}

	compare_hash = sig_hash;

	if (cipher == L_KEY_RSA_PKCS1_V1_5) {
		ssize_t unpad_len;

		unpad_len = unpad(sig_hash, NULL, hash_len, 0, 0x01, false);
		if (unpad_len < 0) {
			success = false;
			goto done;
		}

		compare_hash += hash_len - unpad_len;
		hash_len = unpad_len;
	}

	success = (len_data == (size_t)hash_len) &&
		(memcmp(data, compare_hash, hash_len) == 0);
done:
	l_free(sig_hash);

	return success;
}

LIB_EXPORT struct l_keyring *l_keyring_new(enum l_keyring_type type,
						const struct l_keyring *trusted)
{
	struct l_keyring *keyring;
	char *description;
	char *payload = NULL;
	size_t payload_length = 0;

	if (!internal_keyring && !setup_internal_keyring())
		return NULL;

	if (type == L_KEYRING_TRUSTED_ASYM) {
		if (!trusted)
			return NULL;

		payload = l_strdup_printf(
			"restrict=asymmetric:key_or_keyring:%d",
			trusted->serial);
		payload_length = strlen(payload);
	} else if (type != L_KEYRING_SIMPLE) {
		/* Unsupported type */
		return NULL;
	}

	keyring = l_new(struct l_keyring, 1);
	keyring->type = type;
	description = l_strdup_printf("ell-keyring-%p", keyring);
	keyring->serial = kernel_add_key("keyring", description, payload,
						payload_length,
						internal_keyring);
	l_free(description);
	l_free(payload);

	if (keyring->serial < 0) {
		l_free(keyring);
		keyring = NULL;
	}

	return keyring;
}

LIB_EXPORT void l_keyring_free(struct l_keyring *keyring)
{
	if (unlikely(!keyring))
		return;

	kernel_revoke_key(keyring->serial);

	l_free(keyring);
}

bool l_keyring_link(struct l_keyring *keyring, const struct l_key *key)
{
	long error;

	if (unlikely(!keyring) || unlikely(!key))
		return false;

	error = kernel_link_key(key->serial, keyring->serial);

	return error == 0;
}

bool l_keyring_unlink(struct l_keyring *keyring, const struct l_key *key)
{
	long error;

	if (unlikely(!keyring) || unlikely(!key))
		return false;

	error = kernel_unlink_key(key->serial, keyring->serial);

	return error == 0;
}
