/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
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

#include <assert.h>
#include <linux/types.h>
#include <netinet/ip.h>
#include <linux/if_arp.h>

#include <ell/ell.h>
#include "ell/dhcp6-private.h"

static uint8_t client_packet[1024];
static size_t client_packet_len;

static const uint8_t expected_iaid[] = { 0x03, 0x04, 0x05, 0x06 };

static const uint8_t advertise_no_address[] = {
	0x02, 0xfc, 0xd6, 0xaf, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01,
	0x26, 0xa3, 0x58, 0x38, 0x08, 0x00, 0x27, 0x2c, 0x64, 0xc8, 0x00, 0x02,
	0x00, 0x12, 0x00, 0x02, 0x00, 0x00, 0x0d, 0xe9, 0x47, 0x32, 0x30, 0x41,
	0x33, 0x32, 0x38, 0x30, 0x30, 0x30, 0x30, 0x32, 0x00, 0x11, 0x00, 0x27,
	0x00, 0x00, 0x0d, 0xe9, 0x00, 0x01, 0x00, 0x1f, 0x68, 0x74, 0x74, 0x70,
	0x73, 0x3a, 0x2f, 0x2f, 0x61, 0x63, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x64,
	0x2e, 0x67, 0x66, 0x73, 0x76, 0x63, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63,
	0x77, 0x6d, 0x70, 0x00, 0x0d, 0x00, 0x02, 0x00, 0x06, 0x00, 0x0d, 0x00,
	0x02, 0x00, 0x02, 0x00, 0x17, 0x00, 0x10, 0xfd, 0xaa, 0x88, 0x52, 0x00,
	0x88, 0x00, 0x01, 0xfa, 0x8f, 0xca, 0xff, 0xfe, 0x40, 0x87, 0x0c, 0x00,
	0x18, 0x00, 0x06, 0x04, 0x68, 0x6f, 0x6d, 0x65, 0x00
};

static void test_option_parsing(const void *data)
{
	struct dhcp6_message *message =
		(struct dhcp6_message *) advertise_no_address;
	size_t len = sizeof(advertise_no_address);
	struct dhcp6_option_iter iter;
	uint16_t t;
	uint16_t l;
	const void *v;

	assert(_dhcp6_option_iter_init(&iter, message, len));

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_CLIENT_ID);
	assert(l == 14);

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_SERVER_ID);
	assert(l == 18);

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_VENDOR_OPTS);
	assert(l == 39);

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_STATUS_CODE);
	assert(l == 2);

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_STATUS_CODE);
	assert(l == 2);

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_DNS_SERVERS);
	assert(l == 16);

	assert(_dhcp6_option_iter_next(&iter, &t, &l, &v));
	assert(t == L_DHCP6_OPTION_DOMAIN_LIST);
	assert(l == 6);

	assert(!_dhcp6_option_iter_next(&iter, &t, &l, &v));
}

static const uint8_t solicit_data_1[] = {
	0x01, 0x84, 0xec, 0xce, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x03, 0x00, 0x0c, 0x03, 0x04,
	0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
	0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x52, 0x00, 0x08, 0x00, 0x02,
	0x00, 0x00
};

static const uint8_t advertise_data_1[] = {
	0x02, 0x08, 0xd9, 0xc2, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x03,
	0x00, 0x01, 0x10, 0xc3, 0x7b, 0x54, 0x74, 0xd0, 0x00, 0x03, 0x00, 0x28,
	0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0xa8, 0xc0, 0x00, 0x01, 0x27, 0x50,
	0x00, 0x05, 0x00, 0x18, 0x26, 0x05, 0x60, 0x00, 0x10, 0x25, 0x60, 0xeb,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0xfd, 0x00, 0x01, 0x51, 0x80,
	0x00, 0x01, 0x51, 0x80, 0x00, 0x0d, 0x00, 0x09, 0x00, 0x00, 0x73, 0x75,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x00, 0x07, 0x00, 0x01, 0xff, 0x00, 0x17,
	0x00, 0x10, 0x26, 0x05, 0x60, 0x00, 0x10, 0x25, 0x60, 0xeb, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static const uint8_t request_data_1[] = {
	0x03, 0x67, 0x8b, 0xed, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x03,
	0x00, 0x01, 0x10, 0xc3, 0x7b, 0x54, 0x74, 0xd0, 0x00, 0x03, 0x00, 0x28,
	0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x05, 0x00, 0x18, 0x26, 0x05, 0x60, 0x00, 0x10, 0x25, 0x60, 0xeb,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0xfd, 0x00, 0x01, 0x51, 0x80,
	0x00, 0x01, 0x51, 0x80, 0x00, 0x06, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18,
	0x00, 0x52, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00
};

static const uint8_t reply_data_1[] = {
	0x07, 0x67, 0x8b, 0xed, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x03,
	0x00, 0x01, 0x10, 0xc3, 0x7b, 0x54, 0x74, 0xd0, 0x00, 0x03, 0x00, 0x28,
	0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0xa8, 0xc0, 0x00, 0x01, 0x27, 0x50,
	0x00, 0x05, 0x00, 0x18, 0x26, 0x05, 0x60, 0x00, 0x10, 0x25, 0x60, 0xeb,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0xfd, 0x00, 0x01, 0x51, 0x80,
	0x00, 0x01, 0x51, 0x80, 0x00, 0x0d, 0x00, 0x09, 0x00, 0x00, 0x73, 0x75,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x00, 0x17, 0x00, 0x10, 0x26, 0x05, 0x60,
	0x00, 0x10, 0x25, 0x60, 0xeb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01
};

static void test_lease_parsing(const void *data)
{
	struct dhcp6_message *message =
		(struct dhcp6_message *) advertise_data_1;
	size_t len = sizeof(advertise_data_1);
	struct dhcp6_option_iter iter;
	struct l_dhcp6_lease *lease;
	char *address;
	char **dns;

	assert(_dhcp6_option_iter_init(&iter, message, len));

	lease = _dhcp6_lease_parse_options(&iter, expected_iaid);
	assert(lease);

	address = l_dhcp6_lease_get_address(lease);
	assert(address);
	assert(!strcmp(address, "2605:6000:1025:60eb::1bfd"));
	l_free(address);

	dns = l_dhcp6_lease_get_dns(lease);
	assert(dns);
	assert(dns[0]);
	assert(!dns[1]);
	assert(!strcmp(dns[0], "2605:6000:1025:60eb::1"));
	l_strfreev(dns);

	_dhcp6_lease_free(lease);
}

static bool dhcp6_message_compare(const uint8_t *expected, size_t expected_len,
				const uint8_t *obtained, size_t obtained_len)
{
	struct dhcp6_message *e = (struct dhcp6_message *) expected;
	struct dhcp6_message *o = (struct dhcp6_message *) obtained;

	if (expected_len != obtained_len)
		return false;

	if (e->msg_type != o->msg_type)
		return false;

	return !memcmp(e->options, o->options,
				expected_len - sizeof(struct dhcp6_message));
}


static int fake_transport_send(struct dhcp6_transport *transport,
				const struct in6_addr *dest,
				const void *data, size_t len)
{
	assert(len <= sizeof(client_packet));
	memcpy(client_packet, data, len);
	client_packet_len = len;

	return len;
}

static bool event_handler_called;

static void event_handler_lease_obtained(struct l_dhcp6_client *client,
						enum l_dhcp6_client_event event,
						void *userdata)
{
	assert(client);
	assert(event == L_DHCP6_CLIENT_EVENT_LEASE_OBTAINED);
	event_handler_called = true;
}

#define FEED_RX_DATA(packet)  \
	memcpy(transaction_id, client_packet + 1, sizeof(transaction_id)); \
	memcpy(client_packet, packet, sizeof(packet)); \
	memcpy(client_packet + 1, transaction_id, sizeof(transaction_id)); \
	transport->rx_cb(client_packet, sizeof(packet), client) \

static void test_obtain_lease(const void *data)
{
	static const uint8_t addr[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	uint8_t transaction_id[3];
	struct dhcp6_transport *transport = l_new(struct dhcp6_transport, 1);
	const struct l_dhcp6_lease *lease;
	struct l_dhcp6_client *client;

	transport->send = fake_transport_send;
	transport->ifindex = 42;

	client = l_dhcp6_client_new(42);
	assert(l_dhcp6_client_set_address(client, ARPHRD_ETHER, addr, 6));
	assert(_dhcp6_client_set_transport(client, transport));
	assert(l_dhcp6_client_set_event_handler(client,
				event_handler_lease_obtained, NULL, NULL));
	assert(l_dhcp6_client_set_nodelay(client, true));
	assert(l_dhcp6_client_set_lla_randomized(client, true));

	assert(l_dhcp6_client_start(client));

	assert(dhcp6_message_compare(solicit_data_1, sizeof(solicit_data_1),
					client_packet, client_packet_len));

	FEED_RX_DATA(advertise_data_1);

	assert(dhcp6_message_compare(request_data_1, sizeof(request_data_1),
					client_packet, client_packet_len));

	event_handler_called = false;
	FEED_RX_DATA(reply_data_1);
	assert(event_handler_called);

	lease = l_dhcp6_client_get_lease(client);
	assert(lease);

	l_dhcp6_client_destroy(client);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("option parsing", test_option_parsing, NULL);
	l_test_add("lease parsing", test_lease_parsing, NULL);
	l_test_add("obtain lease - no rapid commit", test_obtain_lease, NULL);

	return l_test_run();
}
