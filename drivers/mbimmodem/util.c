/*
 * oFono - Open Source Telephony
 * Copyright (C) 2017  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdint.h>
#include <stdbool.h>

#include "src/common.h"
#include "simutil.h"
#include "mbim.h"
#include "util.h"

int mbim_data_class_to_tech(uint32_t n)
{
	if (n & MBIM_DATA_CLASS_LTE)
		return ACCESS_TECHNOLOGY_EUTRAN;

	if (n & (MBIM_DATA_CLASS_HSUPA | MBIM_DATA_CLASS_HSDPA))
		return ACCESS_TECHNOLOGY_UTRAN_HSDPA_HSUPA;

	if (n & MBIM_DATA_CLASS_HSUPA)
		return ACCESS_TECHNOLOGY_UTRAN_HSUPA;

	if (n & MBIM_DATA_CLASS_HSDPA)
		return ACCESS_TECHNOLOGY_UTRAN_HSDPA;

	if (n & MBIM_DATA_CLASS_UMTS)
		return ACCESS_TECHNOLOGY_UTRAN;

	if (n & MBIM_DATA_CLASS_EDGE)
		return ACCESS_TECHNOLOGY_GSM_EGPRS;

	if (n & MBIM_DATA_CLASS_GPRS)
		return ACCESS_TECHNOLOGY_GSM;

	return -1;
}

uint8_t *mbim_get_fileid_new(enum mbim_app_type app_type, uint32_t fileid, int *file_id_len)
{
	uint8_t parent_path[6] = {0};
	int fileid_len = 0;
	uint8_t *full_path;

	if (app_type == MBIM_APP_USIM || app_type == MBIM_APP_ISIM)
		fileid_len = sim_ef_db_get_path_3g(fileid, parent_path);
	else
		fileid_len = sim_ef_db_get_path_2g(fileid, parent_path);

	if (fileid_len < 2 || fileid_len > 6) {
		*file_id_len = 0;
		return NULL;
	}

	full_path = l_malloc(fileid_len + 2);
	memcpy(full_path, parent_path, fileid_len);

	full_path[fileid_len] = (fileid >> 8) & 0xFF;
	full_path[fileid_len + 1] = fileid & 0xFF;
	*file_id_len = fileid_len + 2;

	return full_path;
}
