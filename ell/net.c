/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#include <sys/socket.h>
#include <linux/if_arp.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "net.h"
#include "net-private.h"
#include "string.h"
#include "utf8.h"
#include "private.h"

/**
 * SECTION:net
 * @short_description: Network Interface related utilities
 *
 * Network Interface utilities
 */

/**
 * l_net_get_mac_address:
 * @ifindex: Interface index to query
 * @out_addr: Buffer to copy the mac address to.  Must be able to hold 6 bytes
 *
 * Obtains the mac address of the network interface given by @ifindex
 *
 * Returns: #true on success and #false on failure
 **/
LIB_EXPORT bool l_net_get_mac_address(uint32_t ifindex, uint8_t *out_addr)
{
	struct ifreq ifr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return false;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;

	err = ioctl(sk, SIOCGIFNAME, &ifr);
	if (err < 0)
		goto error;

	err = ioctl(sk, SIOCGIFHWADDR, &ifr);
	if (err < 0)
		goto error;

	close(sk);

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
		return false;

	memcpy(out_addr, ifr.ifr_hwaddr.sa_data, 6);
	return true;

error:
	close(sk);
	return false;
}

/**
 * l_net_get_name:
 * @ifindex: Interface index to query
 *
 * Obtains the name of the network inderface given by @ifindex
 *
 * Returns: A newly allocated string with the name or NULL on failure
 **/
LIB_EXPORT char *l_net_get_name(uint32_t ifindex)
{
	struct ifreq ifr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return NULL;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;

	err = ioctl(sk, SIOCGIFNAME, &ifr);
	close(sk);

	if (err < 0)
		return NULL;

	return l_strdup(ifr.ifr_name);
}

/**
 * l_net_hostname_is_root:
 * @hostname: Hostname to validate
 *
 * Identifies if the hostname given by @hostname is root domain name or
 * not.
 *
 * Returns: #true if the given hostname is root and #false otherwise.
 **/
LIB_EXPORT bool l_net_hostname_is_root(const char *hostname)
{
	if (unlikely(!hostname))
		return false;

	if (!strcmp(hostname, ""))
		return true;

	if (!strcmp(hostname, "."))
		return true;

	return false;
}

static bool str_has_suffix(const char *str, const char *suffix)
{
	size_t str_len;
	size_t suffix_len;
	size_t len_diff;

	str_len = strlen(str);
	suffix_len = strlen(suffix);

	if (str_len < suffix_len)
		return false;

	len_diff = str_len - suffix_len;

	return !strcasecmp(&str[len_diff], suffix);
}

/**
 * l_net_hostname_is_localhost:
 * @hostname: Hostname to validate
 *
 * Identifies if the hostname given by @hostname is localhost or not.
 *
 * Returns: #true if the given hostname is localhost and #false otherwise.
 **/
LIB_EXPORT bool l_net_hostname_is_localhost(const char *hostname)
{
	if (unlikely(!hostname))
		return false;

	if (!strcasecmp(hostname, "localhost") ||
			!strcasecmp(hostname, "localhost.") ||
			!strcasecmp(hostname, "localhost.localdomain") ||
			!strcasecmp(hostname, "localhost.localdomain."))
		return true;

	if (str_has_suffix(hostname, ".localhost") ||
			str_has_suffix(hostname, ".localhost.") ||
			str_has_suffix(hostname, ".localhost.localdomain") ||
			str_has_suffix(hostname, ".localhost.localdomain."))
		return true;

	return false;
}

static const char *domain_name_escape(const uint8_t *label, uint8_t l)
{
	/* RFC 1035, Section 3.1: "...limit the label to 63 octets or less." */
	static char buf[63 * 4 + 1];
	unsigned int i;
	unsigned int j;

	for (i = 0, j = 0; i < l; i++) {
		if (l_ascii_isalnum(label[i]) ||
				label[i] == '_' || label[i] == '-') {
			buf[j++] = label[i];
			continue;
		}

		if (label[i] == '.' || label[i] == '\\') {
			buf[j++] = '\\';
			buf[j++] = label[i];
			continue;
		}

		buf[j++] = '\\';
		buf[j++] = '0' + label[i] / 100;
		buf[j++] = '0' + (label[i] / 10) % 10;
		buf[j++] = '0' + label[i] % 10;
	}

	buf[j] = '\0';

	return buf;
}

static int validate_next_domain_name(const uint8_t *raw, size_t raw_len)
{
	const uint8_t *p;
	unsigned int r;

	if (raw_len <= 1)
		return -EBADMSG;

	/* Treat NULL domains as invalid */
	if (raw[0] == 0)
		return -EBADMSG;

	p = raw;
	r = raw_len;

	while (r) {
		uint8_t skip = *p;

		r -= 1;
		p += 1;

		if (skip > r)
			return -EBADMSG;

		if (skip > 63)
			return -EINVAL;

		if (skip == 0)
			break;

		r -= skip;
		p += skip;

		/* domains must end with a null label */
		if (!r)
			return -EBADMSG;
	}

	r = p - raw;
	if (r > 255)
		return -EMSGSIZE;

	return r;
}

/*
 * Parse the domain name encoded according to RFC 1035 Section 3.1
 */
char *net_domain_name_parse(const uint8_t *raw, size_t raw_len)
{
	int r;
	struct l_string *growable;
	const uint8_t *p;
	bool first = true;

	r = validate_next_domain_name(raw, raw_len);
	if (r < 0 || (size_t) r != raw_len)
		return NULL;

	growable = l_string_new(r);
	p = raw;

	while (*p) {
		if (first)
			first = false;
		else
			l_string_append_c(growable, '.');

		l_string_append(growable, domain_name_escape(p + 1, *p));
		p += *p + 1;
	}

	return l_string_unwrap(growable);
}

/*
 * Parse list of domain names encoded according to RFC 1035 Section 3.1
 */
char **net_domain_list_parse(const uint8_t *raw, size_t raw_len)
{
	size_t remaining = raw_len;
	const uint8_t *p = raw;
	int r;
	char **ret;
	unsigned int nitems = 0;
	struct l_string *growable = NULL;

	while (remaining) {
		r = validate_next_domain_name(p, remaining);
		if (r < 0)
			return NULL;

		p += r;
		remaining -= r;
		nitems += 1;
	}

	ret = l_new(char *, nitems + 1);
	p = raw;
	remaining = raw_len;
	nitems = 0;

	while (remaining) {
		remaining -= *p + 1;

		if (*p == 0) {
			p += 1;
			ret[nitems++] = l_string_unwrap(growable);
			growable = NULL;
			continue;
		}

		if (!growable)
			growable = l_string_new(128);
		else
			l_string_append_c(growable, '.');

		l_string_append(growable, domain_name_escape(p + 1, *p));
		p += *p + 1;
	}

	return ret;
}
