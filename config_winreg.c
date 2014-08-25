/*
 * WPA Supplicant / Configuration backend: Windows registry
 * Copyright (c) 2003-2005, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 *
 * This file implements a configuration backend for Windows registry.. All the
 * configuration information is stored in the registry and the format for
 * network configuration fields is same as described in the sample
 * configuration file, wpa_supplicant.conf.
 *
 * Configuration data is in HKEY_LOCAL_MACHINE\SOFTWARE\wpa_supplicant\configs
 * key. Each configuration profile has its own key under this. In terms of text
 * files, each profile would map to a separate text file with possibly multiple
 * networks. Under each profile, there is a networks key that lists all
 * networks as a subkey. Each network has set of values in the same way as
 * network block in the configuration file. In addition, blobs subkey has
 * possible blobs as values.
 *
 * HKEY_LOCAL_MACHINE\SOFTWARE\wpa_supplicant\configs\test\networks\0000
 *    ssid="example"
 *    key_mgmt=WPA-PSK
 */

#include "includes.h"

#include "common.h"
#include "wpa.h"
#include "wpa_supplicant.h"
#include "config.h"

#define KEY_ROOT HKEY_LOCAL_MACHINE
#define KEY_PREFIX "SOFTWARE\\wpa_supplicant"


static int wpa_config_read_blobs(struct wpa_config *config, HKEY hk)
{
	struct wpa_config_blob *blob;
	int errors = 0;
	HKEY bhk;
	LONG ret;
	DWORD i;

	ret = RegOpenKeyEx(hk, "blobs", 0, KEY_QUERY_VALUE, &bhk);
	if (ret != ERROR_SUCCESS) {
		wpa_printf(MSG_DEBUG, "Could not open wpa_supplicant config "
			   "blobs key");
		return 0; /* assume no blobs */
	}

	for (i = 0; ; i++) {
		char name[255], data[4096];
		DWORD namelen, datalen, type;

		namelen = sizeof(name);
		datalen = sizeof(data);
		ret = RegEnumValue(bhk, i, name, &namelen, NULL, &type,
				   data, &datalen);

		if (ret == ERROR_NO_MORE_ITEMS)
			break;

		if (ret != ERROR_SUCCESS) {
			wpa_printf(MSG_DEBUG, "RegEnumValue failed: 0x%x",
				   (unsigned int) ret);
			break;
		}

		if (namelen >= sizeof(name))
			namelen = sizeof(name) - 1;
		name[namelen] = '\0';

		if (datalen >= sizeof(data))
			datalen = sizeof(data) - 1;
		data[datalen] = '\0';

		wpa_printf(MSG_MSGDUMP, "blob %d: field='%s' len %d",
			   (int) i, name, (int) datalen);

		blob = malloc(sizeof(*blob));
		if (blob == NULL) {
			errors++;
			break;
		}
		memset(blob, 0, sizeof(*blob));
		blob->name = strdup(name);
		blob->data = malloc(datalen);
		if (blob->name == NULL || blob->data == NULL) {
			wpa_config_free_blob(blob);
			errors++;
			break;
		}
		memcpy(blob->data, data, datalen);

		wpa_config_set_blob(config, blob);
	}

	RegCloseKey(bhk);

	return errors ? -1 : 0;
}


static int wpa_config_read_reg_dword(HKEY hk, const char *name, int *_val)
{
	DWORD val, buflen;
	LONG ret;

	buflen = sizeof(val);
	ret = RegQueryValueEx(hk, name, NULL, NULL, (LPBYTE) &val, &buflen);
	if (ret == ERROR_SUCCESS && buflen == sizeof(val)) {
		wpa_printf(MSG_DEBUG, "%s=%d", name, (int) val);
		*_val = val;
		return 0;
	}

	return -1;
}


static int wpa_config_read_global(struct wpa_config *config, HKEY hk)
{
	int errors = 0;

	wpa_config_read_reg_dword(hk, "ap_scan", &config->ap_scan);
	wpa_config_read_reg_dword(hk, "fast_reauth", &config->fast_reauth);
	wpa_config_read_reg_dword(hk, "dot11RSNAConfigPMKLifetime",
				  &config->dot11RSNAConfigPMKLifetime);
	wpa_config_read_reg_dword(hk, "dot11RSNAConfigPMKReauthThreshold",
				  &config->dot11RSNAConfigPMKReauthThreshold);
	wpa_config_read_reg_dword(hk, "dot11RSNAConfigSATimeout",
				  &config->dot11RSNAConfigSATimeout);
	wpa_config_read_reg_dword(hk, "update_config", &config->update_config);

	if (wpa_config_read_reg_dword(hk, "eapol_version",
				      &config->eapol_version) == 0) {
		if (config->eapol_version < 1 ||
		    config->eapol_version > 2) {
			wpa_printf(MSG_ERROR, "Invalid EAPOL version (%d)",
				   config->eapol_version);
			errors++;
		}
	}

	return errors ? -1 : 0;
}


static struct wpa_ssid * wpa_config_read_network(HKEY hk, const char *netw,
						 int id)
{
	HKEY nhk;
	LONG ret;
	DWORD i;
	struct wpa_ssid *ssid;
	int errors = 0;

	ret = RegOpenKeyEx(hk, netw, 0, KEY_QUERY_VALUE, &nhk);
	if (ret != ERROR_SUCCESS) {
		wpa_printf(MSG_DEBUG, "Could not open wpa_supplicant config "
			   "network '%s'", netw);
		return NULL;
	}

	wpa_printf(MSG_MSGDUMP, "Start of a new network '%s'", netw);
	ssid = (struct wpa_ssid *) malloc(sizeof(*ssid));
	if (ssid == NULL) {
		RegCloseKey(nhk);
		return NULL;
	}
	memset(ssid, 0, sizeof(*ssid));
	ssid->id = id;

	wpa_config_set_network_defaults(ssid);

	for (i = 0; ; i++) {
		TCHAR name[255], data[1024];
		DWORD namelen, datalen, type;

		namelen = 255;
		datalen = 1024;
		ret = RegEnumValue(nhk, i, name, &namelen, NULL, &type,
				   data, &datalen);

		if (ret == ERROR_NO_MORE_ITEMS)
			break;

		if (ret != ERROR_SUCCESS) {
			wpa_printf(MSG_ERROR, "RegEnumValue failed: 0x%x",
				   (unsigned int) ret);
			break;
		}

		if (namelen >= 255)
			namelen = 255 - 1;
		name[namelen] = '\0';

		if (datalen >= 1024)
			datalen = 1024 - 1;
		data[datalen] = '\0';

		if (wpa_config_set(ssid, name, data, 0) < 0)
			errors++;
	}

	RegCloseKey(nhk);

	if (ssid->passphrase) {
		if (ssid->psk_set) {
			wpa_printf(MSG_ERROR, "Both PSK and passphrase "
				   "configured for network '%s'.", netw);
			errors++;
		}
		wpa_config_update_psk(ssid);
	}

	if ((ssid->key_mgmt & WPA_KEY_MGMT_PSK) && !ssid->psk_set) {
		wpa_printf(MSG_ERROR, "WPA-PSK accepted for key management, "
			   "but no PSK configured for network '%s'.", netw);
		errors++;
	}

	if ((ssid->group_cipher & WPA_CIPHER_CCMP) &&
	    !(ssid->pairwise_cipher & WPA_CIPHER_CCMP)) {
		/* Group cipher cannot be stronger than the pairwise cipher. */
		wpa_printf(MSG_DEBUG, "Removed CCMP from group cipher "
			   "list since it was not allowed for pairwise "
			   "cipher for network '%s'.", netw);
		ssid->group_cipher &= ~WPA_CIPHER_CCMP;
	}

	if (errors) {
		free(ssid);
		ssid = NULL;
	}

	return ssid;
}


static int wpa_config_read_networks(struct wpa_config *config, HKEY hk)
{
	HKEY nhk;
	struct wpa_ssid *ssid, *tail = NULL, *head = NULL;
	int errors = 0;
	LONG ret;
	DWORD i;

	ret = RegOpenKeyEx(hk, "networks", 0, KEY_ENUMERATE_SUB_KEYS, &nhk);
	if (ret != ERROR_SUCCESS) {
		wpa_printf(MSG_ERROR, "Could not open wpa_supplicant networks "
			   "registry key");
		return -1;
	}

	for (i = 0; ; i++) {
		TCHAR name[255];
		DWORD namelen;

		namelen = 255;
		ret = RegEnumKeyEx(nhk, i, name, &namelen, NULL, NULL, NULL,
				   NULL);

		if (ret == ERROR_NO_MORE_ITEMS)
			break;

		if (ret != ERROR_SUCCESS) {
			wpa_printf(MSG_DEBUG, "RegEnumKeyEx failed: 0x%x",
				   (unsigned int) ret);
			break;
		}

		if (namelen >= 255)
			namelen = 255 - 1;
		name[namelen] = '\0';

		ssid = wpa_config_read_network(nhk, name, i);
		if (ssid == NULL) {
			wpa_printf(MSG_ERROR, "Failed to parse network "
				   "profile '%s'.", name);
			errors++;
			continue;
		}
		if (head == NULL) {
			head = tail = ssid;
		} else {
			tail->next = ssid;
			tail = ssid;
		}
		if (wpa_config_add_prio_network(config, ssid)) {
			wpa_printf(MSG_ERROR, "Failed to add network profile "
				   "'%s' to priority list.", name);
			errors++;
			continue;
		}
	}

	RegCloseKey(nhk);

	config->ssid = head;

	return errors ? -1 : 0;
}


struct wpa_config * wpa_config_read(const char *name)
{
	char buf[256];
	int errors = 0;
	struct wpa_config *config;
	struct wpa_ssid *ssid;
	int prio;
	HKEY hk;
	LONG ret;

	config = wpa_config_alloc_empty(NULL, NULL);
	if (config == NULL)
		return NULL;
	wpa_printf(MSG_DEBUG, "Reading configuration profile '%s'", name);

	snprintf(buf, sizeof(buf), KEY_PREFIX "\\configs\\%s", name);
	ret = RegOpenKeyEx(KEY_ROOT, buf, 0, KEY_QUERY_VALUE, &hk);
	if (ret != ERROR_SUCCESS) {
		wpa_printf(MSG_ERROR, "Could not open wpa_supplicant "
			   "configuration registry %s", buf);
		free(config);
		return NULL;
	}

	if (wpa_config_read_global(config, hk))
		errors++;

	if (wpa_config_read_networks(config, hk))
		errors++;

	if (wpa_config_read_blobs(config, hk))
		errors++;

	for (prio = 0; prio < config->num_prio; prio++) {
		ssid = config->pssid[prio];
		wpa_printf(MSG_DEBUG, "Priority group %d",
			   ssid->priority);
		while (ssid) {
			wpa_printf(MSG_DEBUG, "   id=%d ssid='%s'",
				   ssid->id,
				   wpa_ssid_txt(ssid->ssid, ssid->ssid_len));
			ssid = ssid->pnext;
		}
	}

	if (errors) {
		wpa_config_free(config);
		config = NULL;
	}

	return config;
}


int wpa_config_write(const char *name, struct wpa_config *config)
{
	wpa_printf(MSG_DEBUG, "Writing configuration file '%s' - "
		   "NOT YET IMPLEMENTED", name);
	/* TODO */
	return -1;
}
