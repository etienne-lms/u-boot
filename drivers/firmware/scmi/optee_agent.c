// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2020 Linaro Limited.
 */

#include <common.h>
#include <dm.h>
#include <errno.h>
#include <scmi_agent.h>
#include <scmi_agent-uclass.h>
#include <tee.h>
#include <asm/types.h>
#include <dm/devres.h>
#include <linux/arm-smccc.h>
#include <linux/compat.h>

#include "smt.h"

#define SCMI_SHM_SIZE		128

#define WITH_DEPRECATED_PTA_CMDS

struct scmi_optee_channel {
	struct udevice *tee;
	u32 tee_session;
	u32 agent_id;
	struct tee_shm *shm;
#ifdef WITH_DEPRECATED_PTA_CMDS
	struct scmi_smt smt;
	u32 channel_id;
#endif
};

#define TA_SCMI_UUID { 0xa8cfe406, 0xd4f5, 0x4a2e, \
		      { 0x9f, 0x8d, 0xa2, 0x5d, 0xc7, 0x54, 0xc0, 0x99 } }

/*
 * API of commands supported the SCMI TA in OP-TEE
 *
 * TA_CMD_GET_CHANNEL - Get channel identifer for a buffer pool
 * [in]     value[0].a - Agent ID
 *
 * TA_CMD_PROCESS_CHANNEL - Process message in SCMI channel
 * [in]     value[0].a - Channel ID
 * [in/out] memref[1] - Message buffer
 *
 * TA_CMD_PROCESS_MESSAGE - Process message from SCMI agent
 * [in]     value[0].a - Agent ID
 * [in/out] memref[1] - Message buffer
 */
#define TA_CMD_GET_CHANNEL_ID		0x1
#define TA_CMD_PROCESS_CHANNEL		0x2
#define TA_CMD_PROCESS_MESSAGE		0x3

static int tee_ret2errno(u32 tee_retval)
{
	switch (tee_retval) {
	case TEE_SUCCESS:
		return 0;
	case TEE_ERROR_SHORT_BUFFER:
		return -ETOOSMALL;
	case TEE_ERROR_OUT_OF_MEMORY:
		return -ENOMEM;
	case TEE_ERROR_ITEM_NOT_FOUND:
		return -ENOENT;
	default:
		return -EPROTO;
	}
}

static int open_optee_session(struct scmi_optee_channel *chan)
{
	struct udevice *tee = NULL;
	const struct tee_optee_ta_uuid uuid = TA_SCMI_UUID;

	struct tee_open_session_arg arg;
	int rc = 0;

	if (chan->tee)
		return 0;

	tee = tee_find_device(tee, NULL, NULL, NULL);
	if (!tee)
		return -ENODEV;

	memset(&arg, 0, sizeof(arg));
	tee_optee_ta_uuid_to_octets(arg.uuid, &uuid);
	rc = tee_open_session(tee, &arg, 0, NULL);
	if (rc) {
		dev_err(chan->dev, "SCMI OP-TEE session failed\n");

		return rc;
	}

	chan->tee = tee;
	chan->tee_session = arg.session;

	return 0;
}

#ifdef WITH_DEPRECATED_PTA_CMDS
static int get_optee_channel(struct scmi_optee_channel *chan)
{
	struct tee_invoke_arg arg;
	struct tee_param param[3];

	if (!chan || !chan->tee)
		return -EINVAL;

	memset(&arg, 0, sizeof(arg));
	arg.func = TA_CMD_GET_CHANNEL_ID;
	arg.session = chan->tee_session;

	memset(param, 0, sizeof(param));
	param[0].attr = TEE_PARAM_ATTR_TYPE_VALUE_INOUT;
	param[0].u.value.a = chan->channel_id;			// TODO; check that: Vince's change
	param[1].attr = TEE_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[1].u.value.a = (u64)(uintptr_t)chan->smt.buf >> 32;
	param[1].u.value.b = (u32)chan->smt.buf;
	param[2].attr = TEE_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[2].u.value.a = chan->smt.size;

	if (tee_invoke_func(chan->tee, &arg, ARRAY_SIZE(param), param)) {
		dev_err(chan->dev, "SCMI OP-TEE get channel failed\n");
		return -EIO;
	}

	if (!arg.ret)
		chan->channel_id = param[0].u.value.a;

	return tee_ret2errno(arg.ret);
}
#endif //WITH_DEPRECATED_PTA_CMDS

static struct scmi_optee_channel *scmi_optee_get_priv(struct udevice *dev)
{
	return (struct scmi_optee_channel *)dev_get_priv(dev);
}

static int scmi_optee_process_msg(struct udevice *dev, struct scmi_msg *msg)
{
	struct scmi_optee_channel *chan = scmi_optee_get_priv(dev);
	struct tee_invoke_arg arg;
	struct tee_param param[2];
#ifdef WITH_DEPRECATED_PTA_CMDS
	struct scmi_smt_header *hdr = (void *)chan->smt.buf;
#else
	struct scmi_smt_header *hdr = chan->shm->addr;
	struct scmi_smt smt = {
		.buf = chan->shm->addr,
		.size = chan->shm->size,
	};
#endif
	int rc;

	if (!chan->tee)
		return -ENODEV;

#ifndef WITH_DEPRECATED_PTA_CMDS
	scmi_write_msg_to_smt(dev, &smt, msg);
#else
	if (!(hdr->channel_status & SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE)) {
		dev_err(dev, "SCMI channel busy\n");
		return -EBUSY;
	}

	if ((!msg->in_msg && msg->in_msg_sz) ||
	    (!msg->out_msg && msg->out_msg_sz))
		return -EINVAL;

	if (chan->smt.size < (sizeof(*hdr) + msg->in_msg_sz) ||
	    chan->smt.size < (sizeof(*hdr) + msg->out_msg_sz)) {
		dev_err(dev, "buffer too small\n");
		return -ETOOSMALL;
	}

	hdr->channel_status &= ~SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE;
	hdr->length = msg->in_msg_sz + sizeof(hdr->msg_header);
	hdr->msg_header = SMT_HEADER_TOKEN(0) |
			  SMT_HEADER_MESSAGE_TYPE(0) |
			  SMT_HEADER_PROTOCOL_ID(msg->protocol_id) |
			  SMT_HEADER_MESSAGE_ID(msg->message_id);

	memcpy(hdr->msg_payload, msg->in_msg, msg->in_msg_sz);
#endif

	memset(&arg, 0, sizeof(arg));
#ifdef WITH_DEPRECATED_PTA_CMDS
	arg.func = TA_CMD_PROCESS_CHANNEL;
#else
	arg.func = TA_CMD_PROCESS_MESSAGE;
#endif
	arg.session = chan->tee_session;

	memset(param, 0, sizeof(param));
	param[0].attr = TEE_PARAM_ATTR_TYPE_VALUE_INPUT;
#ifdef WITH_DEPRECATED_PTA_CMDS
	param[0].u.value.a = chan->channel_id;
#else
	param[0].u.value.a = chan->agent_id;
#endif

#ifndef WITH_DEPRECATED_PTA_CMDS
	param[1].attr = TEE_PARAM_ATTR_TYPE_MEMREF_INOUT;
	param[1].u.memref.shm = chan->shm;
	param[1].u.memref.size = chan->shm->size;
#endif

	rc = tee_invoke_func(chan->tee, &arg, ARRAY_SIZE(param), param);
	if (rc) {
		dev_err(chan->dev, "SCMI OP-TEE msg: invocation failed\n");
	} else if (hdr->channel_status & SCMI_SHMEM_CHAN_STAT_CHANNEL_ERROR) {
		dev_err(chan->dev, "SCMI OP-TEE msg: channel error\n");
		rc = -EIO;
	} else {
		rc = tee_ret2errno(arg.ret);
	}

	if (!rc) {
		if (hdr->length > msg->out_msg_sz + sizeof(hdr->msg_header))
			return -ETOOSMALL;

		msg->out_msg_sz = hdr->length - sizeof(hdr->msg_header);
		memcpy(msg->out_msg, hdr->msg_payload, msg->out_msg_sz);
	}

#ifdef WITH_DEPRECATED_PTA_CMDS
	scmi_clear_smt_channel(&chan->smt);
#else
	scmi_clear_smt_channel(&smt);
#endif


	return rc;
}

static int alloc_shm(struct scmi_optee_channel *chan)
{
	struct tee_shm *shm = NULL;
	struct scmi_smt_header *hdr = NULL;
	int rc = 0;

	rc = tee_shm_alloc(chan->tee, SCMI_SHM_SIZE, TEE_SHM_ALLOC, &shm);
	if (rc)
		return rc;

	chan->shm = shm;

	memset(chan->shm->addr, 0, SCMI_SHM_SIZE);
	hdr = chan->shm->addr;
	hdr->channel_status |= SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE;

	/*
	 * Note: let OP-TEE device removal unregister the shared memory
	 * when exiting U-Boot execution.
	 */
	return 0;
}

static int scmi_optee_remove(struct udevice *dev)
{
	struct scmi_optee_channel *chan = scmi_optee_get_priv(dev);
	int rc = 0;

	if (chan && chan->tee) {
		rc = tee_close_session(chan->tee, chan->tee_session);
		if (rc)
			return rc;

		chan->tee = NULL;
	}

	return 0;
}

static int scmi_optee_probe(struct udevice *dev)
{
	struct scmi_optee_channel *chan = scmi_optee_get_priv(dev);
	u32 channel_id;
	int rc;

	if (dev_read_u32(dev, "agent-id", &channel_id)) {
		dev_info(dev, "No channel ID specified, assume 0\n");
	} else {
#ifdef WITH_DEPRECATED_PTA_CMDS
		chan->channel_id = channel_id;
#endif
		chan->agent_id = channel_id;
	}

#ifdef WITH_DEPRECATED_PTA_CMDS
	rc = scmi_dt_get_smt_buffer(dev, &chan->smt);
	if (rc) {
		dev_err(dev, "Failed to get smt resources: %d\n", rc);
		goto out;
	}
#endif

	rc = open_optee_session(chan);
	if (rc)
		goto out;

#ifdef WITH_DEPRECATED_PTA_CMDS
	rc = get_optee_channel(chan);
	if (rc)
		goto out;
#endif

	rc = alloc_shm(chan);
out:
	if (rc) {
		free_shm(chan);
		devm_kfree(dev, chan);
	}

	return rc;
}

static const struct udevice_id scmi_optee_ids[] = {
	{ .compatible = "linaro,scmi-optee" },
	{ }
};

static const struct scmi_agent_ops scmi_optee_ops = {
	.process_msg = scmi_optee_process_msg,
};

U_BOOT_DRIVER(scmi_optee) = {
	.name		= "scmi-over-optee",
	.id		= UCLASS_SCMI_AGENT,
	.of_match	= scmi_optee_ids,
	.priv_auto_alloc_size = sizeof(struct scmi_optee_channel),
	.probe		= scmi_optee_probe,
	.remove		= scmi_optee_remove,
	.flags		= DM_FLAG_OS_PREPARE,
	.ops		= &scmi_optee_ops,
};
