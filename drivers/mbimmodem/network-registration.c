/*
 * oFono - Open Source Telephony
 * Copyright (C) 2017  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/netreg.h>

#include "src/common.h"

#include "drivers/mbimmodem/mbim.h"
#include "drivers/mbimmodem/mbim-message.h"
#include "drivers/mbimmodem/mbimmodem.h"

struct netreg_data {
	struct mbim_device *device;
	struct l_idle *delayed_register;
};

static inline int register_state_to_status(uint32_t register_state)
{
	switch (register_state) {
	case 0:	/* MBIMRegisterStateUnknown */
		return NETWORK_REGISTRATION_STATUS_UNKNOWN;
	case 1: /* MBIMRegisterStateDeregistered */
		return NETWORK_REGISTRATION_STATUS_NOT_REGISTERED;
	case 2: /* MBIMRegisterStateSearching */
		return NETWORK_REGISTRATION_STATUS_SEARCHING;
	case 3: /* MBIMRegisterStateHome */
		return NETWORK_REGISTRATION_STATUS_REGISTERED;
	case 4: /* MBIMRegisterStateRoaming */
	case 5: /* MBIMRegisterStatePartner */
		return NETWORK_REGISTRATION_STATUS_ROAMING;
	case 6: /* MBIMRegisterStateDenied */
		return NETWORK_REGISTRATION_STATUS_DENIED;
	}

	return NETWORK_REGISTRATION_STATUS_UNKNOWN;
}

static void mbim_register_state_changed(struct mbim_message *message,
								void *user)
{
	struct ofono_netreg *netreg = user;
	uint32_t nw_error;
	uint32_t register_state;
	uint32_t register_mode;
	uint32_t available_data_classes;
	int status;
	int tech;

	DBG("");

	if (!mbim_message_get_arguments(message, "uuuu",
						&nw_error, &register_state,
						&register_mode,
						&available_data_classes))
		return;

	DBG("NwError: %u, RegisterMode: %u", nw_error, register_mode);

	status = register_state_to_status(register_state);
	tech = mbim_data_class_to_tech(available_data_classes);

	ofono_netreg_status_notify(netreg, status, -1, -1, tech);
}

static void mbim_registration_status_cb(struct mbim_message *message,
								void *user)
{
	struct cb_data *cbd = user;
	ofono_netreg_status_cb_t cb = cbd->cb;
	uint32_t dummy;
	uint32_t register_state;
	uint32_t available_data_classes;
	int status;
	int tech;

	DBG("");

	if (mbim_message_get_error(message) != 0)
		goto error;

	if (!mbim_message_get_arguments(message, "uuuu",
						&dummy, &register_state,
						&dummy,
						&available_data_classes))
		goto error;

	status = register_state_to_status(register_state);
	tech = mbim_data_class_to_tech(available_data_classes);

	CALLBACK_WITH_SUCCESS(cb, status, -1, -1, tech, cbd->data);
	return;
error:
	CALLBACK_WITH_FAILURE(cb, -1, -1, -1, -1, cbd->data);
}

static void mbim_registration_status(struct ofono_netreg *netreg,
					ofono_netreg_status_cb_t cb,
					void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct mbim_message *message;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_REGISTER_STATE,
					MBIM_COMMAND_TYPE_QUERY);
	mbim_message_set_arguments(message, "");

	if (mbim_device_send(nd->device, NETREG_GROUP, message,
				mbim_registration_status_cb, cbd, l_free) > 0)
		return;

	l_free(cbd);
	mbim_message_unref(message);
	CALLBACK_WITH_FAILURE(cb, -1, -1, -1, -1, data);
}

static void mbim_current_operator_cb(struct mbim_message *message, void *user)
{
	struct cb_data *cbd = user;
	ofono_netreg_operator_cb_t cb = cbd->cb;
	struct ofono_network_operator op;
	uint32_t dummy;
	uint32_t register_state;
	uint32_t available_data_classes;
	L_AUTO_FREE_VAR(char *, provider_id) = NULL;
	L_AUTO_FREE_VAR(char *, provider_name) = NULL;
	L_AUTO_FREE_VAR(char *, roaming_text) = NULL;

	DBG("");

	if (mbim_message_get_error(message) != 0)
		goto error;

	if (!mbim_message_get_arguments(message, "uuuuusss",
						&dummy, &register_state, &dummy,
						&available_data_classes, &dummy,
						&provider_id, &provider_name,
						&roaming_text))
		goto error;

	if (register_state < 3 || register_state > 5)
		goto error;

	DBG("provider: %s(%s)", provider_name, provider_id);

	/* If MBIMRegisterStateRoaming or MBIMRegisterStatePartner */
	if (register_state == 4 || register_state == 5)
		DBG("roaming text: %s", roaming_text);

	strncpy(op.name, provider_name, OFONO_MAX_OPERATOR_NAME_LENGTH);
	op.name[OFONO_MAX_OPERATOR_NAME_LENGTH] = '\0';

	strncpy(op.mcc, provider_id, OFONO_MAX_MCC_LENGTH);
	op.mcc[OFONO_MAX_MCC_LENGTH] = '\0';

	strncpy(op.mnc, provider_id + OFONO_MAX_MCC_LENGTH,
						OFONO_MAX_MNC_LENGTH);
	op.mnc[OFONO_MAX_MNC_LENGTH] = '\0';

	/* Set to current */
	op.status = 2;
	op.tech = mbim_data_class_to_tech(available_data_classes);

	CALLBACK_WITH_SUCCESS(cb, &op, cbd->data);
	return;
error:
	CALLBACK_WITH_FAILURE(cb, NULL, cbd->data);
}

static void mbim_current_operator(struct ofono_netreg *netreg,
				ofono_netreg_operator_cb_t cb, void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct mbim_message *message;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_REGISTER_STATE,
					MBIM_COMMAND_TYPE_QUERY);
	mbim_message_set_arguments(message, "");

	if (mbim_device_send(nd->device, NETREG_GROUP, message,
				mbim_current_operator_cb, cbd, l_free) > 0)
		return;

	l_free(cbd);
	mbim_message_unref(message);
	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void mbim_list_operators_cb(struct mbim_message *message,
						void *user)
{
	struct cb_data *cb = user;
	ofono_netreg_operator_list_cb_t cb_func = cb->cb;
	struct ofono_network_operator *list = NULL;

	uint32_t providers_count, provider_state, cellular_class;
	uint32_t rssi, error_rate;
	char *provider_id, *provider_name;
	struct mbim_message_iter iter;
	int i = 0;

	if (!mbim_message_get_arguments(message, "ua(susuuu)", &providers_count, &iter)) {
		CALLBACK_WITH_FAILURE(cb_func, 0, NULL, cb->data);
		return;
	}

	list = l_new(struct ofono_network_operator, providers_count);

	while (mbim_message_iter_next_entry(&iter, &provider_id, &provider_state,
							&provider_name, &cellular_class, &rssi, &error_rate)) {

		strcpy(list[i].name, provider_name);
		strncpy(list[i].mcc, provider_id, OFONO_MAX_MCC_LENGTH);
		list[i].mcc[OFONO_MAX_MCC_LENGTH] = '\0';

		strncpy(list[i].mnc, provider_id + OFONO_MAX_MCC_LENGTH, OFONO_MAX_MNC_LENGTH);
		list[i].mnc[OFONO_MAX_MNC_LENGTH] = '\0';

		list[i].status = mbim_provider_state_to_status(provider_state);
		list[i].tech = -1;

		i++;
	}

	if (list)
		CALLBACK_WITH_SUCCESS(cb_func, providers_count, list, cb->data);
	else
		CALLBACK_WITH_FAILURE(cb_func, 0, NULL, cb->data);
}

static void mbim_list_operators(struct ofono_netreg *netreg,
					ofono_netreg_operator_list_cb_t cb, void *user_data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	struct mbim_message *message;

	message = mbim_message_new(mbim_uuid_basic_connect,
						MBIM_CID_VISIBLE_PROVIDERS,
						MBIM_COMMAND_TYPE_QUERY);
	/* "0" is a full scan, whereas "1" means a restricted scan */
	mbim_message_set_arguments(message, "u", 0);

	if (mbim_device_send(nd->device, NETREG_GROUP, message,
						mbim_list_operators_cb, cbd, l_free) > 0)
		return;

	l_free(cbd);
	mbim_message_unref(message);
	CALLBACK_WITH_FAILURE(cb, 0, NULL, user_data);
}

static void mbim_register_state_set_cb(struct mbim_message *message, void *user)
{
	struct cb_data *cbd = user;
	ofono_netreg_register_cb_t cb = cbd->cb;

	DBG("");

	if (mbim_message_get_error(message) != 0)
		CALLBACK_WITH_FAILURE(cb, cbd->data);
	else
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void mbim_register_auto(struct ofono_netreg *netreg,
				ofono_netreg_register_cb_t cb, void *data)
{
	static const uint32_t data_class = MBIM_DATA_CLASS_GPRS |
						MBIM_DATA_CLASS_EDGE |
						MBIM_DATA_CLASS_UMTS |
						MBIM_DATA_CLASS_HSDPA |
						MBIM_DATA_CLASS_HSUPA |
						MBIM_DATA_CLASS_LTE;
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct mbim_message *message;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_REGISTER_STATE,
					MBIM_COMMAND_TYPE_SET);
	mbim_message_set_arguments(message, "suu", NULL,
					MBIM_REGISTER_TYPE_AUTOMATIC, data_class);

	if (mbim_device_send(nd->device, NETREG_GROUP, message,
				mbim_register_state_set_cb, cbd, l_free) > 0)
		return;

	l_free(cbd);
	mbim_message_unref(message);
	CALLBACK_WITH_FAILURE(cb, data);
}

static void mbim_register_manual(struct ofono_netreg *netreg,
				const char *mcc, const char *mnc,
				ofono_netreg_register_cb_t cb, void *data)
{
	static const uint32_t data_class = MBIM_DATA_CLASS_GPRS |
						MBIM_DATA_CLASS_EDGE |
						MBIM_DATA_CLASS_UMTS |
						MBIM_DATA_CLASS_HSDPA |
						MBIM_DATA_CLASS_HSUPA |
						MBIM_DATA_CLASS_LTE;
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct mbim_message *message;
	L_AUTO_FREE_VAR(char *, provider_id) = NULL;

	DBG("");

	provider_id = l_strdup_printf("%s%s", mcc, mnc);

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_REGISTER_STATE,
					MBIM_COMMAND_TYPE_SET);
	mbim_message_set_arguments(message, "suu", provider_id,
					MBIM_REGISTER_TYPE_MANUAL, data_class);

	if (mbim_device_send(nd->device, NETREG_GROUP, message,
				mbim_register_state_set_cb, cbd, l_free) > 0)
		return;

	l_free(cbd);
	mbim_message_unref(message);
	CALLBACK_WITH_FAILURE(cb, data);
}

static inline int convert_signal_strength(uint32_t strength)
{
	if (strength == 99)
		return -1;

	return strength * 100 / 31;
}

static void mbim_signal_state_query_cb(struct mbim_message *message, void *user)
{
	struct cb_data *cbd = user;
	ofono_netreg_strength_cb_t cb = cbd->cb;
	uint32_t strength;

	DBG("");

	if (mbim_message_get_error(message) != 0)
		goto error;

	if (!mbim_message_get_arguments(message, "u", &strength))
		goto error;

	CALLBACK_WITH_SUCCESS(cb, convert_signal_strength(strength), cbd->data);
	return;

error:
	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
}

static void mbim_signal_strength(struct ofono_netreg *netreg,
				ofono_netreg_strength_cb_t cb, void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct mbim_message *message;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_SIGNAL_STATE,
					MBIM_COMMAND_TYPE_QUERY);
	mbim_message_set_arguments(message, "");

	if (mbim_device_send(nd->device, NETREG_GROUP, message,
				mbim_signal_state_query_cb, cbd, l_free) > 0)
		return;

	l_free(cbd);
	mbim_message_unref(message);
	CALLBACK_WITH_FAILURE(cb, -1, data);
}

static void mbim_signal_state_changed(struct mbim_message *message, void *user)
{
	struct ofono_netreg *netreg = user;
	uint32_t strength;
	uint32_t error_rate;
	uint32_t signal_strength_interval;
	uint32_t rssi_threshold;

	DBG("");

	if (!mbim_message_get_arguments(message, "uuuu",
						&strength, &error_rate,
						&signal_strength_interval,
						&rssi_threshold))
		return;

	DBG("strength: %u, error_rate: %u", strength, error_rate);
	DBG("strength interval: %u, rssi_threshold: %u",
				signal_strength_interval, rssi_threshold);

	ofono_netreg_strength_notify(netreg, convert_signal_strength(strength));
}

static void delayed_register(struct l_idle *idle, void *user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct netreg_data *nd = ofono_netreg_get_data(netreg);

	DBG("");

	l_idle_remove(idle);
	nd->delayed_register = NULL;

	if (!mbim_device_register(nd->device, NETREG_GROUP,
					mbim_uuid_basic_connect,
					MBIM_CID_SIGNAL_STATE,
					mbim_signal_state_changed,
					netreg, NULL))
		goto error;

	if (!mbim_device_register(nd->device, NETREG_GROUP,
					mbim_uuid_basic_connect,
					MBIM_CID_REGISTER_STATE,
					mbim_register_state_changed,
					netreg, NULL))
		goto error;

	ofono_netreg_register(netreg);
	return;

error:
	ofono_netreg_remove(netreg);
}

static int mbim_netreg_probe(struct ofono_netreg *netreg, unsigned int vendor,
					void *data)
{
	struct mbim_device *device = data;
	struct netreg_data *nd = l_new(struct netreg_data, 1);

	DBG("");

	nd->device = mbim_device_ref(device);
	nd->delayed_register = l_idle_create(delayed_register, netreg, NULL);

	ofono_netreg_set_data(netreg, nd);

	return 0;
}

static void mbim_netreg_remove(struct ofono_netreg *netreg)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);

	DBG("");

	ofono_netreg_set_data(netreg, NULL);

	l_idle_remove(nd->delayed_register);
	mbim_device_cancel_group(nd->device, NETREG_GROUP);
	mbim_device_unregister_group(nd->device, NETREG_GROUP);
	mbim_device_unref(nd->device);
	nd->device = NULL;
	l_free(nd);
}

static const struct ofono_netreg_driver driver = {
	.probe				= mbim_netreg_probe,
	.remove				= mbim_netreg_remove,
	.registration_status		= mbim_registration_status,
	.current_operator		= mbim_current_operator,
	.list_operators			= mbim_list_operators,
	.register_auto			= mbim_register_auto,
	.register_manual		= mbim_register_manual,
	.strength			= mbim_signal_strength,
};

OFONO_ATOM_DRIVER_BUILTIN(netreg, mbim, &driver)
