// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
/*
 * Copyright (C) 2018, STMicroelectronics - All Rights Reserved
 */

#include <common.h>
#include <dm.h>
#include <ram.h>

DECLARE_GLOBAL_DATA_PTR;

int dram_init(void)
{
	struct ram_info ram;
	struct udevice *dev;
	int ret;

	ret = uclass_get_device(UCLASS_RAM, 0, &dev);
	if (ret) {
		debug("RAM init failed: %d\n", ret);
		return ret;
	}
	ret = ram_get_info(dev, &ram);
	if (ret) {
		debug("Cannot get RAM size: %d\n", ret);
		return ret;
	}
	debug("RAM init base=%lx, size=%x\n", ram.base, ram.size);

	gd->ram_size = ram.size;

	return 0;
}

ulong board_get_usable_ram_top(ulong total_size)
{
	int off, node;
	fdt_addr_t reg;


	off = fdt_path_offset(gd->fdt_blob, "/reserved-memory/");
	if (off < 0)
		return gd->ram_top;

	for (node = fdt_first_subnode(gd->fdt_blob, off);
	     node >= 0;
	     node = fdt_next_subnode(gd->fdt_blob, node)) {
		if (!strncmp(fdt_get_name(gd->fdt_blob, node, NULL),
			     "optee@", 6)) {
			reg = fdtdec_get_addr(gd->fdt_blob, node, "reg");
			if (reg != FDT_ADDR_T_NONE)
				return reg;
		}
	}


	return gd->ram_top;
}
