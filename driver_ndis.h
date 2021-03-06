/*
 * WPA Supplicant - Windows/NDIS driver interface
 * Copyright (c) 2004-2005, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef DRIVER_NDIS_H
#define DRIVER_NDIS_H

#ifdef CONFIG_NDIS_EVENTS_INTEGRATED
struct ndis_events_data;
struct ndis_events_data * ndis_events_init(HANDLE *read_pipe, HANDLE *event);
void ndis_events_deinit(struct ndis_events_data *events);
#endif /* CONFIG_NDIS_EVENTS_INTEGRATED */

struct ndis_pmkid_entry {
	struct ndis_pmkid_entry *next;
	u8 bssid[ETH_ALEN];
	u8 pmkid[16];
};

struct wpa_driver_ndis_data {
	void *ctx;
	char ifname[100];
	u8 own_addr[ETH_ALEN];
	LPADAPTER adapter;
	u8 bssid[ETH_ALEN];

	int has_capability;
	int no_of_pmkid;
	int radio_enabled;
	struct wpa_driver_capa capa;
	struct ndis_pmkid_entry *pmkid;
#ifndef CONFIG_NDIS_EVENTS_INTEGRATED
	int event_sock;
#endif /* CONFIG_NDIS_EVENTS_INTEGRATED */
	char *adapter_desc;
	int wired;
#ifdef CONFIG_NDIS_EVENTS_INTEGRATED
	HANDLE events_pipe, event_avail;
	struct ndis_events_data *events;
#endif /* CONFIG_NDIS_EVENTS_INTEGRATED */
};

#endif /* DRIVER_NDIS_H */
