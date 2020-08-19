// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2019-2020 Linaro Limited
 */
#include <common.h>
#include <dm.h>
#include <errno.h>
#include <reset-uclass.h>
#include <scmi.h>
#include <asm/types.h>

#define SCMI_RD_NAME_LEN		16

#define SCMI_RD_RESET_FLAG_ASSERT	BIT(1)
#define SCMI_RD_RESET_FLAG_DEASSERT	0

enum scmi_reset_domain_message_id {
	SCMI_RESET_DOMAIN_ATTRIBUTES = 0x3,
	SCMI_RESET_DOMAIN_RESET = 0x4,
};

/**
 * struct scmi_rd_attr_in - Payload for RESET_DOMAIN_ATTRIBUTES message
 * @domain_id:	SCMI reset domain ID
 */
struct scmi_rd_attr_in {
	u32 domain_id;
};

/**
 * struct scmi_rd_attr_out - Payload for RESET_DOMAIN_ATTRIBUTES response
 * @status:	SCMI command status
 * @attributes:	Retrieved attributes of the reset domain
 * @latency:	Reset cycle max lantency
 * @name:	Reset domain name
 */
struct scmi_rd_attr_out {
	s32 status;
	u32 attributes;
	u32 latency;
	char name[SCMI_RD_NAME_LEN];
};

/**
 * struct scmi_rd_reset_in - Message payload for RESET command
 * @domain_id:		SCMI reset domain ID
 * @flags:		Flags for the reset request
 * @reset_state:	Reset target state
 */
struct scmi_rd_reset_in {
	u32 domain_id;
	u32 flags;
	u32 reset_state;
};

/**
 * struct scmi_rd_reset_out - Response payload for RESET command
 * @status:	SCMI command status
 */
struct scmi_rd_reset_out {
	s32 status;
};

static int scmi_reset_set_state(struct reset_ctl *rst, int assert_not_deassert)
{
	struct scmi_rd_reset_in in = {
		.domain_id = rst->id,
		.flags = assert_not_deassert ? SCMI_RD_RESET_FLAG_ASSERT :
			 SCMI_RD_RESET_FLAG_DEASSERT,
		.reset_state = 0,
	};
	struct scmi_rd_reset_out out;
	struct scmi_msg scmi_msg = {
		.protocol_id = SCMI_PROTOCOL_ID_RESET_DOMAIN,
		.message_id = SCMI_RESET_DOMAIN_RESET,
		.in_msg = (u8 *)&in,
		.in_msg_sz = sizeof(in),
		.out_msg = (u8 *)&out,
		.out_msg_sz = sizeof(out),
	};
	int ret;

	ret = scmi_send_and_process_msg(rst->dev->parent, &scmi_msg);
	if (ret)
		return ret;

	return scmi_to_linux_errno(out.status);
}

static int scmi_reset_assert(struct reset_ctl *rst)
{
	return scmi_reset_set_state(rst, SCMI_RD_RESET_FLAG_ASSERT);
}

static int scmi_reset_deassert(struct reset_ctl *rst)
{
	return scmi_reset_set_state(rst, SCMI_RD_RESET_FLAG_DEASSERT);
}

static int scmi_reset_request(struct reset_ctl *rst)
{
	struct scmi_rd_attr_in in = {
		.domain_id = rst->id,
	};
	struct scmi_rd_attr_out out;
	struct scmi_msg scmi_msg = {
		.protocol_id = SCMI_PROTOCOL_ID_RESET_DOMAIN,
		.message_id = SCMI_RESET_DOMAIN_RESET,
		.in_msg = (u8 *)&in,
		.in_msg_sz = sizeof(in),
		.out_msg = (u8 *)&out,
		.out_msg_sz = sizeof(out),
	};
	int ret;

	/*
	 * We don't really care about the attribute, just check
	 * the reset domain exists.
	 */
	ret = scmi_send_and_process_msg(rst->dev->parent, &scmi_msg);
	if (ret)
		return ret;

	return scmi_to_linux_errno(out.status);
}

static int scmi_reset_rfree(struct reset_ctl *rst)
{
	return 0;
}

static const struct reset_ops scmi_reset_domain_ops = {
	.request	= scmi_reset_request,
	.rfree		= scmi_reset_rfree,
	.rst_assert	= scmi_reset_assert,
	.rst_deassert	= scmi_reset_deassert,
};

U_BOOT_DRIVER(scmi_reset_domain) = {
	.name = "scmi_reset_domain",
	.id = UCLASS_RESET,
	.ops = &scmi_reset_domain_ops,
};
