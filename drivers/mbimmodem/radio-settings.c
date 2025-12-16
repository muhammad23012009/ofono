#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/radio-settings.h>

#include "drivers/mbimmodem/mbim.h"
#include "drivers/mbimmodem/mbim-message.h"
#include "drivers/mbimmodem/mbimmodem.h"

struct rat_data {
    struct mbim_device *device;
    struct l_idle *delayed_register;
};


static void query_rat_mode_cb(struct mbim_message *message, void *user)
{
    struct cb_data *cbd = user;
    ofono_radio_settings_rat_mode_query_cb_t cb = cbd->cb;
    uint32_t dummy;
    uint32_t rat_mode = 0;
    L_AUTO_FREE_VAR(char *, dummy_str) = NULL;
    L_AUTO_FREE_VAR(char *, dummy_str2) = NULL;
    L_AUTO_FREE_VAR(char *, dummy_str3) = NULL;

    DBG("");

    if (mbim_message_get_error(message) != 0)
        goto error;

    if (!mbim_message_get_arguments(message, "uuuuusssuu", &dummy, &dummy,
                                    &dummy, &dummy, &dummy, &dummy_str,
                                    &dummy_str2, &dummy_str3, &dummy, &rat_mode))
        goto error;

    if (rat_mode & MBIM_DATA_CLASS_LTE)
        rat_mode = OFONO_RADIO_ACCESS_MODE_LTE;
    else if (rat_mode & MBIM_DATA_CLASS_UMTS)
        rat_mode = OFONO_RADIO_ACCESS_MODE_UMTS;
    else if (rat_mode & (MBIM_DATA_CLASS_GPRS | MBIM_DATA_CLASS_EDGE))
        rat_mode = OFONO_RADIO_ACCESS_MODE_GSM;
    else
        rat_mode = OFONO_RADIO_ACCESS_MODE_ANY;

    CALLBACK_WITH_SUCCESS(cb, rat_mode, cbd->data);
    return;

error:
    CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
}

static void mbim_query_rat_mode(struct ofono_radio_settings *rs,
            ofono_radio_settings_rat_mode_query_cb_t cb,
            void *user_data)
{
    struct rat_data *rd = ofono_radio_settings_get_data(rs);
    struct cb_data *cbd = cb_data_new(cb, user_data);
    uint16_t mbimex_version = ofono_modem_get_integer(ofono_radio_settings_get_modem(rs),
                                                "MBIMExVersion");
    struct mbim_message *message;

    DBG("");

    if (!mbim_device_mbimex_version_at_least(mbimex_version, 2, 0)) {
        /* MBIMEx version < 2.0 does not support RAT mode querying */
        CALLBACK_WITH_FAILURE(cb, -1, user_data);
        return;
    }

    message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_REGISTER_STATE,
					MBIM_COMMAND_TYPE_QUERY);
	mbim_message_set_arguments(message, "");

    if (mbim_device_send(rd->device, RADIO_SETTINGS_GROUP, message,
                query_rat_mode_cb, cbd, l_free) > 0)
        return;

    l_free(cbd);
    mbim_message_unref(message);
    CALLBACK_WITH_FAILURE(cb, -1, user_data);
}

static void query_available_rats_cb(struct mbim_message *message, void *user)
{
    struct cb_data *cbd = user;
    ofono_radio_settings_available_rats_query_cb_t cb = cbd->cb;
    uint32_t dummy;
    uint32_t cellular_class;
    uint32_t available_rats;
    uint32_t ofono_rats = 0;

    DBG("");

    if (mbim_message_get_error(message) != 0)
        goto error;

    if (!mbim_message_get_arguments(message, "uuuuu", &dummy, &cellular_class,
                                    &dummy, &dummy, &available_rats))
        goto error;

    if (cellular_class & 1) /* MbimCellularClassGsm */
        ofono_rats |= OFONO_RADIO_ACCESS_MODE_GSM;

    if (available_rats & MBIM_DATA_CLASS_LTE)
        ofono_rats |= OFONO_RADIO_ACCESS_MODE_LTE;

    if (available_rats & MBIM_DATA_CLASS_UMTS)
        ofono_rats |= OFONO_RADIO_ACCESS_MODE_UMTS;

    if (available_rats & (MBIM_DATA_CLASS_GPRS | MBIM_DATA_CLASS_EDGE))
        ofono_rats |= OFONO_RADIO_ACCESS_MODE_GSM;

    CALLBACK_WITH_SUCCESS(cb, ofono_rats, cbd->data);
    return;

error:
    CALLBACK_WITH_FAILURE(cb, 0, cbd->data);
}

static void mbim_query_available_rats(struct ofono_radio_settings *rs,
            ofono_radio_settings_available_rats_query_cb_t cb,
            void *user_data)
{
    struct rat_data *rd = ofono_radio_settings_get_data(rs);
    struct cb_data *cbd = cb_data_new(cb, user_data);
    struct mbim_message *message;

    DBG("");

    message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_DEVICE_CAPS,
					MBIM_COMMAND_TYPE_QUERY);
    mbim_message_set_arguments(message, "");

    if (mbim_device_send(rd->device, RADIO_SETTINGS_GROUP, message,
                query_available_rats_cb, cbd, l_free) > 0)
        return;

    l_free(cbd);
    mbim_message_unref(message);
    CALLBACK_WITH_FAILURE(cb, 0, user_data);
}

static void delayed_register(struct l_idle *idle, void *user_data)
{
    struct ofono_radio_settings *rs = user_data;
    struct rat_data *rd = ofono_radio_settings_get_data(rs);

    l_idle_remove(rd->delayed_register);
    rd->delayed_register = NULL;

    ofono_radio_settings_register(rs);
}

static int mbim_radio_settings_probe(struct ofono_radio_settings *rs,
                    unsigned int vendor,
                    void *data)
{
    struct mbim_device *device = data;
    struct rat_data *rd = l_new(struct rat_data, 1);

    rd->device = mbim_device_ref(device);
    rd->delayed_register = l_idle_create(delayed_register, rs, NULL);

    ofono_radio_settings_set_data(rs, rd);

    return 0;
}

static void mbim_radio_settings_remove(struct ofono_radio_settings *rs)
{
    struct rat_data *rd = ofono_radio_settings_get_data(rs);

    ofono_radio_settings_set_data(rs, NULL);
    l_idle_remove(rd->delayed_register);
    mbim_device_unref(rd->device);
    rd->device = NULL;
    l_free(rd);
}

static const struct ofono_radio_settings_driver driver = {
	.probe		= mbim_radio_settings_probe,
	.remove		= mbim_radio_settings_remove,
	.query_rat_mode = mbim_query_rat_mode,
	.query_available_rats = mbim_query_available_rats,
};

OFONO_ATOM_DRIVER_BUILTIN(radio_settings, mbim, &driver)