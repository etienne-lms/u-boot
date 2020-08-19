// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (C) 2019-2020 Linaro Limited.
 */

#include <common.h>
#include <cpu_func.h>
#include <dm.h>
#include <errno.h>
#include <mailbox.h>
#include <memalign.h>
#include <scmi.h>
#include <tee.h>
#include <asm/system.h>
#include <asm/types.h>
#include <dm/device-internal.h>
#include <dm/devres.h>
#include <dm/lists.h>
#include <dm/ofnode.h>
#include <linux/arm-smccc.h>
#include <linux/compat.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/ioport.h>

#define TIMEOUT_US_10MS			10000

/**
 * enum scmi_transport_channel - Supported SCMI transport layers
 */
enum scmi_transport_channel {
	SCMI_MAILBOX_TRANSPORT,
	SCMI_ARM_SMCCC_TRANSPORT,
	SCMI_OPTEE_TRANSPORT,
};

/**
 * struct error_code - Helper structure for SCMI error code conversion
 * @scmi:	SCMI error code
 * @errno:	Related standard error number
 */
struct error_code {
	int scmi;
	int errno;
};

/**
 * struct method_ops - Operations related to an SCMI transport layer
 * @process_msg:	Send message thru the SCMI transport
 * @remove_agent:	Release SCMI transport resource
 */
struct method_ops {
	int (*process_msg)(struct udevice *dev, struct scmi_msg *msg);
	int (*remove_agent)(struct udevice *dev);
};

/**
 * struct scmi_agent - Description of SCMI agent transport layer
 * @method_ops:		Operations for the transport layer used the agent
 * @method_priv:	Private data for the transport layer used the agent
 */
struct scmi_agent {
	struct method_ops *method_ops;
	void *method_priv;
};

/**
 * struct scmi_smt_header - Description of the shared memory message buffer
 *
 * SMT stands for Shared Memory based Transport.
 * SMT uses 28 byte header prior message payload to handle the state of
 * the communication channel realized by the shared memory area and
 * to define SCMI protocol information the payload relates to.
 */
struct scmi_smt_header {
	__le32 reserved;
	__le32 channel_status;
#define SCMI_SHMEM_CHAN_STAT_CHANNEL_ERROR	BIT(1)
#define SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE	BIT(0)
	__le32 reserved1[2];
	__le32 flags;
#define SCMI_SHMEM_FLAG_INTR_ENABLED		BIT(0)
	__le32 length;
	__le32 msg_header;
	u8 msg_payload[0];
};

#define SMT_HEADER_TOKEN(token)		(((token) << 18) & GENMASK(31, 18))
#define SMT_HEADER_PROTOCOL_ID(proto)	(((proto) << 10) & GENMASK(17, 10))
#define SMT_HEADER_MESSAGE_TYPE(type)	(((type) << 18) & GENMASK(9, 8))
#define SMT_HEADER_MESSAGE_ID(id)	((id) & GENMASK(7, 0))

/**
 * struct scmi_shm_buf - Description of a shared memory buffer
 * @buf:	Shared memory base address
 * @size:	Shared memory byte size
 */
struct scmi_shm_buf {
	u8 *buf;
	size_t size;
};

/**
 * struct scmi_mbox_channel - Description of an SCMI mailbox transport
 * @shm_buf:	Shared memory buffer
 * @mbox:	Mailbox channel description
 * @timeout_us:	Timeout in microseconds for the mailbox transfer
 */
struct scmi_mbox_channel {
	struct scmi_shm_buf shm_buf;
	struct mbox_chan mbox;
	ulong timeout_us;
};

/**
 * struct scmi_arm_smc_channel - Description of an SCMI SMCCC transport
 * @func_id:	SMCCC function ID used by the SCMI transport
 * @shm_buf:	Shared memory buffer
 */
struct scmi_arm_smc_channel {
	ulong func_id;
	struct scmi_shm_buf shm_buf;
};

static const struct error_code scmi_linux_errmap[] = {
	{ .scmi = SCMI_NOT_SUPPORTED, .errno = -EOPNOTSUPP, },
	{ .scmi = SCMI_INVALID_PARAMETERS, .errno = -EINVAL, },
	{ .scmi = SCMI_DENIED, .errno = -EACCES, },
	{ .scmi = SCMI_NOT_FOUND, .errno = -ENOENT, },
	{ .scmi = SCMI_OUT_OF_RANGE, .errno = -ERANGE, },
	{ .scmi = SCMI_BUSY, .errno = -EBUSY, },
	{ .scmi = SCMI_COMMS_ERROR, .errno = -ECOMM, },
	{ .scmi = SCMI_GENERIC_ERROR, .errno = -EIO, },
	{ .scmi = SCMI_HARDWARE_ERROR, .errno = -EREMOTEIO, },
	{ .scmi = SCMI_PROTOCOL_ERROR, .errno = -EPROTO, },
};

int scmi_to_linux_errno(s32 scmi_code)
{
	int n;

	if (!scmi_code)
		return 0;

	for (n = 0; n < ARRAY_SIZE(scmi_linux_errmap); n++)
		if (scmi_code == scmi_linux_errmap[n].scmi)
			return scmi_linux_errmap[1].errno;

	return -EPROTO;
}

/**
 * Get shared memory configuration defined by the referred DT phandle
 * Return with a errno compliant value.
 */
static int get_shm_buffer(struct udevice *dev, struct scmi_shm_buf *shm)
{
	int ret;
	struct ofnode_phandle_args args;
	struct resource resource;
	fdt32_t faddr;
	phys_addr_t paddr;

	ret = dev_read_phandle_with_args(dev, "shmem", NULL, 0, 0, &args);
	if (ret)
		return ret;

	ret = ofnode_read_resource(args.node, 0, &resource);
	if (ret)
		return ret;

	faddr = cpu_to_fdt32(resource.start);
	paddr = ofnode_translate_address(args.node, &faddr);

	shm->size = resource_size(&resource);
	if (shm->size < sizeof(struct scmi_smt_header)) {
		dev_err(dev, "Shared memory buffer too small\n");
		return -EINVAL;
	}

	shm->buf = devm_ioremap(dev, paddr, shm->size);
	if (!shm->buf)
		return -ENOMEM;

	if (dcache_status())
		mmu_set_region_dcache_behaviour((uintptr_t)shm->buf,
						shm->size, DCACHE_OFF);

	return 0;
}

/**
 * Write SCMI message @msg into a SMT shared buffer @shm_buf.
 * Return 0 on success and with a negative errno in case of error.
 */
static int write_msg_to_smt(struct udevice *dev, struct scmi_shm_buf *shm_buf,
			    struct scmi_msg *msg)
{
	struct scmi_smt_header *hdr = (void *)shm_buf->buf;

	if ((!msg->in_msg && msg->in_msg_sz) ||
	    (!msg->out_msg && msg->out_msg_sz))
		return -EINVAL;

	if (!(hdr->channel_status & SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE)) {
		dev_dbg(dev, "Channel busy\n");
		return -EBUSY;
	}

	if (shm_buf->size < (sizeof(*hdr) + msg->in_msg_sz) ||
	    shm_buf->size < (sizeof(*hdr) + msg->out_msg_sz)) {
		dev_dbg(dev, "Buffer too small\n");
		return -ETOOSMALL;
	}

	/* Load message in shared memory */
	hdr->channel_status &= ~SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE;
	hdr->length = msg->in_msg_sz + sizeof(hdr->msg_header);
	hdr->msg_header = SMT_HEADER_TOKEN(0) |
			  SMT_HEADER_MESSAGE_TYPE(0) |
			  SMT_HEADER_PROTOCOL_ID(msg->protocol_id) |
			  SMT_HEADER_MESSAGE_ID(msg->message_id);

	memcpy_toio(hdr->msg_payload, msg->in_msg, msg->in_msg_sz);

	return 0;
}

/**
 * Read SCMI message from a SMT shared buffer @shm_buf and copy it into @msg.
 * Return 0 on success and with a negative errno in case of error.
 */
static int read_resp_from_smt(struct udevice *dev, struct scmi_shm_buf *shm_buf,
			      struct scmi_msg *msg)
{
	struct scmi_smt_header *hdr = (void *)shm_buf->buf;

	if (!(hdr->channel_status & SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE)) {
		dev_err(dev, "Channel unexpectedly busy\n");
		return -EBUSY;
	}

	if (hdr->channel_status & SCMI_SHMEM_CHAN_STAT_CHANNEL_ERROR) {
		dev_err(dev, "Channel error reported, reset channel\n");
		return -ECOMM;
	}

	if (hdr->length > msg->out_msg_sz + sizeof(hdr->msg_header)) {
		dev_err(dev, "Buffer to small\n");
		return -ETOOSMALL;
	}

	/* Get the data */
	msg->out_msg_sz = hdr->length - sizeof(hdr->msg_header);
	memcpy_fromio(msg->out_msg, hdr->msg_payload, msg->out_msg_sz);

	return 0;
}

/**
 * Clear SMT flags in shared buffer to allow further message exchange
 */
static void clear_smt_channel(struct scmi_shm_buf *shm_buf)
{
	struct scmi_smt_header *hdr = (void *)shm_buf->buf;

	hdr->channel_status &= ~SCMI_SHMEM_CHAN_STAT_CHANNEL_ERROR;
}

#ifdef CONFIG_DM_MAILBOX
/*
 * SCMI over mailbox transport
 */

static int mbox_process_msg(struct udevice *dev, struct scmi_msg *msg)
{
	struct scmi_agent *agent = dev_get_priv(dev);
	struct scmi_mbox_channel *chan = agent->method_priv;
	int ret;

	ret = write_msg_to_smt(dev, &chan->shm_buf, msg);
	if (ret)
		return ret;

	/* Give shm addr to mbox in case it is meaningful */
	ret = mbox_send(&chan->mbox, chan->shm_buf.buf);
	if (ret) {
		dev_err(dev, "Message send failed: %d\n", ret);
		goto out;
	}

	/* Receive the response */
	ret = mbox_recv(&chan->mbox, chan->shm_buf.buf, chan->timeout_us);
	if (ret) {
		dev_err(dev, "Response failed: %d, abort\n", ret);
		goto out;
	}

	ret = read_resp_from_smt(dev, &chan->shm_buf, msg);

out:
	clear_smt_channel(&chan->shm_buf);

	return ret;
}

struct method_ops mbox_channel_ops = {
	.process_msg = mbox_process_msg,
};

static int probe_mailbox_channel(struct udevice *dev)
{
	struct scmi_agent *agent = dev_get_priv(dev);
	struct scmi_mbox_channel *chan;
	int ret;

	chan = devm_kzalloc(dev, sizeof(*chan), GFP_KERNEL);
	if (!chan)
		return -ENOMEM;

	chan->timeout_us = TIMEOUT_US_10MS;

	ret = mbox_get_by_index(dev, 0, &chan->mbox);
	if (ret) {
		dev_err(dev, "Failed to find mailbox: %d\n", ret);
		goto out;
	}

	ret = get_shm_buffer(dev, &chan->shm_buf);
	if (ret)
		dev_err(dev, "Failed to get shm resources: %d\n", ret);

out:
	if (ret) {
		devm_kfree(dev, chan);
		return ret;
	}

	agent->method_ops = &mbox_channel_ops;
	agent->method_priv = (void *)chan;

	return 0;
}
#endif /* CONFIG_DM_MAILBOX */

#ifdef CONFIG_ARM_SMCCC
/*
 * SCMI over SMCCC transport
 */

#define SMCCC_RET_NOT_SUPPORTED         ((unsigned long)-1)

static int arm_smc_process_msg(struct udevice *dev, struct scmi_msg *msg)
{
	struct scmi_agent *agent = dev_get_priv(dev);
	struct scmi_arm_smc_channel *chan = agent->method_priv;
	struct arm_smccc_res res;
	int ret;

	ret = write_msg_to_smt(dev, &chan->shm_buf, msg);
	if (ret)
		return ret;

	arm_smccc_smc(chan->func_id, 0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		ret = -ENXIO;
	else
		ret = read_resp_from_smt(dev, &chan->shm_buf, msg);

	clear_smt_channel(&chan->shm_buf);

	return ret;
}

struct method_ops arm_smc_channel_ops = {
	.process_msg = arm_smc_process_msg,
};

static int probe_arm_smc_channel(struct udevice *dev)
{
	struct scmi_agent *agent = dev_get_priv(dev);
	struct scmi_arm_smc_channel *chan;
	u32 func_id;
	int ret;

	chan = devm_kzalloc(dev, sizeof(*chan), GFP_KERNEL);
	if (!chan)
		return -ENOMEM;

	if (dev_read_u32(dev, "arm,smc-id", &func_id)) {
		dev_err(dev, "Missing property func-id\n");
		return -EINVAL;
	}

	chan->func_id = func_id;

	ret = get_shm_buffer(dev, &chan->shm_buf);
	if (ret) {
		dev_err(dev, "Failed to get shm resources: %d\n", ret);
		return ret;
	}

	agent->method_ops = &arm_smc_channel_ops;
	agent->method_priv = (void *)chan;

	return 0;
}
#endif /* CONFIG_ARM_SMCCC */

#ifdef CONFIG_OPTEE
struct scmi_optee_channel {
	struct udevice *tee;
	u32	tee_session;
	u32	channel_id;
	struct	scmi_shm_buf shm_buf;
};

#define TA_SCMI_UUID { 0xa8cfe406, 0xd4f5, 0x4a2e, \
		      { 0x9f, 0x8d, 0xa2, 0x5d, 0xc7, 0x54, 0xc0, 0x99 } }

/*
 * API of commands supported the SCMI TA in OP-TEE
 *
 * TA_CMD_GET_CHANNEL - Get channel identifer for a buffer pool
 * param[0] (in value) - Message buffer physical start address
 * param[1] (in value) - Message buffer byte size
 * param[2] (out value) - value.a: Output channel identifier
 *
 * TA_CMD_PROCESS_CHANNEL - Process message in SCMI channel
 * param[0] (in value) - value.a: SCMI channel identifier
 */
#define TA_CMD_GET_CHANNEL_ID		0x1
#define TA_CMD_PROCESS_CHANNEL		0x2

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
	} else {
		chan->tee = tee;
		chan->tee_session = arg.session;
	}

	return rc;
}

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
	param[1].u.value.a = (u64)(uintptr_t)chan->shm_buf.buf >> 32;
	param[1].u.value.b = (u32)chan->shm_buf.buf;
	param[2].attr = TEE_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[2].u.value.a = chan->shm_buf.size;

	if (tee_invoke_func(chan->tee, &arg, ARRAY_SIZE(param), param)) {
		dev_err(chan->dev, "SCMI OP-TEE get channel failed\n");
		return -EIO;
	}

	if (!arg.ret)
		chan->channel_id = param[0].u.value.a;

	return tee_ret2errno(arg.ret);
}

static int optee_process_msg(struct udevice *dev, struct scmi_msg *msg)
{
	struct scmi_agent *agent = dev_get_priv(dev);
	struct scmi_optee_channel *chan = agent->method_priv;
	struct tee_invoke_arg arg;
	struct tee_param param[1];
	struct scmi_smt_header *hdr = (void *)chan->shm_buf.buf;
	int rc;

	if (!chan->tee)
		return -ENODEV;

	if (!(hdr->channel_status & SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE)) {
		dev_err(dev, "SCMI channel busy\n");
		return -EBUSY;
	}

	if ((!msg->in_msg && msg->in_msg_sz) ||
	    (!msg->out_msg && msg->out_msg_sz))
		return -EINVAL;

	if (chan->shm_buf.size < (sizeof(*hdr) + msg->in_msg_sz) ||
	    chan->shm_buf.size < (sizeof(*hdr) + msg->out_msg_sz)) {
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

	memset(&arg, 0, sizeof(arg));
	arg.func = TA_CMD_PROCESS_CHANNEL;
	arg.session = chan->tee_session;

	memset(param, 0, sizeof(param));
	param[0].attr = TEE_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[0].u.value.a = chan->channel_id;

	rc = tee_invoke_func(chan->tee, &arg, ARRAY_SIZE(param), param);

	if (rc) {
		dev_err(chan->dev, "SCMI OP-TEE msg: invocation failed\n");
	} else if (hdr->channel_status & SCMI_SHMEM_CHAN_STAT_CHANNEL_ERROR) {
		dev_err(chan->dev, "SCMI OP-TEE msg: channel error\n");
		rc = -EIO;
	} else {
		rc = tee_ret2errno(arg.ret);
	}

	hdr->channel_status |= SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE;

	if (!rc) {
		if (hdr->length > msg->out_msg_sz + sizeof(hdr->msg_header))
			return -ETOOSMALL;

		msg->out_msg_sz = hdr->length - sizeof(hdr->msg_header);
		memcpy(msg->out_msg, hdr->msg_payload, msg->out_msg_sz);
	}

	return rc;
}

static int optee_remove_agent(struct udevice *dev)
{
	struct scmi_agent *agent = dev_get_priv(dev);
	struct scmi_optee_channel *chan = agent->method_priv;
	int rc = 0;

	if (chan && chan->tee) {
		rc = tee_close_session(chan->tee, chan->tee_session);
		if (!rc)
			chan->tee = NULL;
	}

	return rc;
}

struct method_ops optee_channel_ops = {
	.process_msg = optee_process_msg,
	.remove_agent = optee_remove_agent,
};

static int probe_optee_channel(struct udevice *dev)
{
	struct scmi_agent *agent = dev_get_priv(dev);
	u32 channel_id;
	struct scmi_optee_channel *chan;
	int rc;

	chan = devm_kzalloc(dev, sizeof(*chan), GFP_KERNEL);
	if (!chan)
		return -ENOMEM;

	if (dev_read_u32(dev, "agent-id", &channel_id))
		dev_info(dev, "No channel ID specified, assume 0\n");
	else
		chan->channel_id = channel_id;

	rc = get_shm_buffer(dev, &chan->shm_buf);
	if (rc) {
		dev_err(dev, "Failed to get shm resources: %d\n", rc);
		goto out;
	}

	rc = open_optee_session(chan);
	if (!rc)
		rc = get_optee_channel(chan);

out:
	if (rc) {
		devm_kfree(dev, chan);
	} else {
		agent->method_ops = &optee_channel_ops;
		agent->method_priv = (void *)chan;
	}

	return rc;
}
#endif /* CONFIG_OPTEE */

int scmi_send_and_process_msg(struct udevice *dev, struct scmi_msg *msg)
{
	struct scmi_agent *agent = dev_get_priv(dev);

	return agent->method_ops->process_msg(dev, msg);
}

static int scmi_remove(struct udevice *dev)
{
	struct scmi_agent *agent = dev_get_priv(dev);

	if (agent->method_ops->remove_agent)
		return agent->method_ops->remove_agent(dev);

	return 0;
}

static int scmi_probe(struct udevice *dev)
{
	switch (dev_get_driver_data(dev)) {
	case SCMI_MAILBOX_TRANSPORT:
		if (IS_ENABLED(CONFIG_DM_MAILBOX))
			return probe_mailbox_channel(dev);
		break;
	case SCMI_ARM_SMCCC_TRANSPORT:
		if (IS_ENABLED(CONFIG_ARM_SMCCC))
			return probe_arm_smc_channel(dev);
		break;
	case SCMI_OPTEE_TRANSPORT:
		if (IS_ENABLED(CONFIG_OPTEE))
			return probe_optee_channel(dev);
	default:
		break;
	}

	return -ENOENT;
}

static int scmi_bind(struct udevice *dev)
{
	int ret = 0;
	ofnode node;
	struct driver *drv;

	dev_for_each_subnode(node, dev) {
		u32 protocol_id;

		if (!ofnode_is_available(node))
			continue;

		if (ofnode_read_u32(node, "reg", &protocol_id))
			continue;

		switch (protocol_id) {
		case SCMI_PROTOCOL_ID_CLOCK:
			drv = DM_GET_DRIVER(scmi_clock);
			break;
		case SCMI_PROTOCOL_ID_RESET_DOMAIN:
			drv = DM_GET_DRIVER(scmi_reset_domain);
			break;
		default:
			dev_info(dev, "Ignore unsupported SCMI protocol %u\n",
				 protocol_id);
			continue;
		}

		ret = device_bind_ofnode(dev, drv, ofnode_get_name(node),
					 NULL, node, NULL);
		if (ret)
			break;
	}

	return ret;
}

static const struct udevice_id scmi_ids[] = {
	{ .compatible = "arm,scmi", .data = SCMI_MAILBOX_TRANSPORT },
	{ .compatible = "arm,scmi-smc", .data = SCMI_ARM_SMCCC_TRANSPORT },
	{ .compatible = "linaro,scmi-optee", .data = SCMI_OPTEE_TRANSPORT },
	{ }
};

U_BOOT_DRIVER(scmi) = {
	.name		= "scmi",
	.id		= UCLASS_FIRMWARE,
	.of_match	= scmi_ids,
	.priv_auto_alloc_size = sizeof(struct scmi_agent),
	.bind		= scmi_bind,
	.probe		= scmi_probe,
	.remove		= scmi_remove,
	.flags		= DM_FLAG_OS_PREPARE,
};
