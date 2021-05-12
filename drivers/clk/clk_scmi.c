// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2019-2020 Linaro Limited
 */
#include <common.h>
#include <clk-uclass.h>
#include <dm.h>
#include <scmi_agent.h>
#include <scmi_protocols.h>
#include <asm/types.h>
#include <linux/clk-provider.h>

static u16 scmi_clk_get_num_clock(struct udevice *dev)
{
	struct scmi_clk_protocol_attr_out out;
	struct scmi_msg msg = {
		.protocol_id = SCMI_PROTOCOL_ID_CLOCK,
		.message_id = SCMI_PROTOCOL_ATTRIBUTES,
		.out_msg = (u8 *)&out,
		.out_msg_sz = sizeof(out),
	};
	int ret;

	ret = devm_scmi_process_msg(dev->parent, &msg);
	if (ret)
		return ret;

	return out.attributes & SCMI_CLK_PROTO_ATTR_COUNT_MASK;
}

static int scmi_clk_get_attibute(struct udevice *dev, int clkid, char **name)
{
	struct scmi_clk_attribute_in in = {
		.clock_id = clkid,
	};
	struct scmi_clk_attribute_out out;
	struct scmi_msg msg = {
		.protocol_id = SCMI_PROTOCOL_ID_CLOCK,
		.message_id = SCMI_CLOCK_ATTRIBUTES,
		.in_msg = (u8 *)&in,
		.in_msg_sz = sizeof(in),
		.out_msg = (u8 *)&out,
		.out_msg_sz = sizeof(out),
	};
	int ret;

	ret = devm_scmi_process_msg(dev->parent, &msg);
	if (ret)
		return ret;

	*name = out.clock_name;

	return 0;
}

static int scmi_clk_gate(struct clk *clk, int enable)
{
	struct scmi_clk_state_in in = {
		.clock_id = clk->id,
		.attributes = enable,
	};
	struct scmi_clk_state_out out;
	struct scmi_msg msg = SCMI_MSG_IN(SCMI_PROTOCOL_ID_CLOCK,
					  SCMI_CLOCK_CONFIG_SET,
					  in, out);
	int ret;

	ret = devm_scmi_process_msg(clk->dev->parent, &msg);
	if (ret)
		return ret;

	return scmi_to_linux_errno(out.status);
}

static int scmi_clk_enable(struct clk *clk)
{
	return scmi_clk_gate(clk, 1);
}

static int scmi_clk_disable(struct clk *clk)
{
	return scmi_clk_gate(clk, 0);
}

static ulong scmi_clk_get_rate(struct clk *clk)
{
	struct scmi_clk_rate_get_in in = {
		.clock_id = clk->id,
	};
	struct scmi_clk_rate_get_out out;
	struct scmi_msg msg = SCMI_MSG_IN(SCMI_PROTOCOL_ID_CLOCK,
					  SCMI_CLOCK_RATE_GET,
					  in, out);
	int ret;

	ret = devm_scmi_process_msg(clk->dev->parent, &msg);
	if (ret < 0)
		return ret;

	ret = scmi_to_linux_errno(out.status);
	if (ret < 0)
		return ret;

	return (ulong)(((u64)out.rate_msb << 32) | out.rate_lsb);
}

static ulong scmi_clk_set_rate(struct clk *clk, ulong rate)
{
	struct scmi_clk_rate_set_in in = {
		.clock_id = clk->id,
		.flags = SCMI_CLK_RATE_ROUND_CLOSEST,
		.rate_lsb = (u32)rate,
		.rate_msb = (u32)((u64)rate >> 32),
	};
	struct scmi_clk_rate_set_out out;
	struct scmi_msg msg = SCMI_MSG_IN(SCMI_PROTOCOL_ID_CLOCK,
					  SCMI_CLOCK_RATE_SET,
					  in, out);
	int ret;

	ret = devm_scmi_process_msg(clk->dev->parent, &msg);
	if (ret < 0)
		return ret;

	ret = scmi_to_linux_errno(out.status);
	if (ret < 0)
		return ret;

	return scmi_clk_get_rate(clk);
}

static struct clk *scmi_clk_register(struct udevice *dev, const char *name)
{
	struct clk *clk;
	int ret;

	clk = kzalloc(sizeof(*clk), GFP_KERNEL);
	if (!clk)
		return ERR_PTR(-ENOMEM);

	ret = clk_register(clk, dev->driver->name, name, dev->name);
	if (ret) {
		kfree(clk);
		return ERR_PTR(ret);
	}

	return clk;
}

static int scmi_clk_probe(struct udevice *dev)
{
	struct clk *clk;
	int num_clocks;
	int i;

	if (!CONFIG_IS_ENABLED(CLK_CCF))
		return 0;

	/* register CCF children: CLK UCLASS, no probed again */
	if (device_get_uclass_id(dev->parent) == UCLASS_CLK)
		return 0;

	num_clocks = scmi_clk_get_num_clock(dev);
	if (!num_clocks)
		return 0;

	for (i = 0; i < num_clocks; i++) {
		char *name;

		if (!scmi_clk_get_attibute(dev, i, &name)) {
			char *clock_name = strdup(name);

			clk = scmi_clk_register(dev, clock_name);
			if (!IS_ERR(clk)) {
				clk->id = i;
				clk_request(dev, clk);
			} else {
				free(clock_name);

				return PTR_ERR(clk);
			}
		}
	}

	return 0;
}

static const struct clk_ops scmi_clk_ops = {
	.enable = scmi_clk_enable,
	.disable = scmi_clk_disable,
	.get_rate = scmi_clk_get_rate,
	.set_rate = scmi_clk_set_rate,
};

U_BOOT_DRIVER(scmi_clock) = {
	.name = "scmi_clk",
	.id = UCLASS_CLK,
	.ops = &scmi_clk_ops,
	.probe = &scmi_clk_probe,
};
