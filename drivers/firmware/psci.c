// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Masahiro Yamada <yamada.masahiro@socionext.com>
 *
 * Based on drivers/firmware/psci.c from Linux:
 * Copyright (C) 2015 ARM Limited
 */

#include <common.h>
#include <command.h>
#include <dm.h>
#include <irq_func.h>
#include <log.h>
#include <dm/lists.h>
#include <efi_loader.h>
#include <linux/delay.h>
#include <linux/libfdt.h>
#include <linux/arm-smccc.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/psci.h>

#define DRIVER_NAME "psci"

unsigned long __efi_runtime invoke_psci_fn
		(unsigned long function_id, unsigned long arg0,
		 unsigned long arg1, unsigned long arg2)
{
	struct arm_smccc_res res;
	enum arm_smccc_conduit conduit;

	conduit = arm_smccc_1_0_invoke(function_id, arg0, arg1, arg2,
				       0, 0, 0, 0, &res);

	if (conduit == SMCCC_CONDUIT_NONE)
		res.a0 = PSCI_RET_DISABLED;

	return res.a0;
}

static int psci_bind(struct udevice *dev)
{
	/* No SYSTEM_RESET support for PSCI 0.1 */
	if (device_is_compatible(dev, "arm,psci-0.2") ||
	    device_is_compatible(dev, "arm,psci-1.0")) {
		int ret;

		/* bind psci-sysreset optionally */
		ret = device_bind_driver(dev, "psci-sysreset", "psci-sysreset",
					 NULL);
		if (ret)
			pr_debug("PSCI System Reset was not bound.\n");
	}

	return 0;
}

static int psci_probe(struct udevice *dev)
{
	return devm_arm_smccc_1_0_set_conduit(dev, "method");
}

/**
 * void do_psci_probe() - probe PSCI firmware driver
 *
 * Ensure that PSC device is probed for SMCCC conduit is be set.
 */
static void __maybe_unused do_psci_probe(void)
{
	struct udevice *dev;

	uclass_get_device_by_name(UCLASS_FIRMWARE, DRIVER_NAME, &dev);
}

#if IS_ENABLED(CONFIG_EFI_LOADER) && IS_ENABLED(CONFIG_PSCI_RESET)
efi_status_t efi_reset_system_init(void)
{
	do_psci_probe();
	return EFI_SUCCESS;
}

void __efi_runtime EFIAPI efi_reset_system(enum efi_reset_type reset_type,
					   efi_status_t reset_status,
					   unsigned long data_size,
					   void *reset_data)
{
	if (reset_type == EFI_RESET_COLD ||
	    reset_type == EFI_RESET_WARM ||
	    reset_type == EFI_RESET_PLATFORM_SPECIFIC) {
		invoke_psci_fn(PSCI_0_2_FN_SYSTEM_RESET, 0, 0, 0);
	} else if (reset_type == EFI_RESET_SHUTDOWN) {
		invoke_psci_fn(PSCI_0_2_FN_SYSTEM_OFF, 0, 0, 0);
	}
	while (1)
		;
}
#endif /* IS_ENABLED(CONFIG_EFI_LOADER) && IS_ENABLED(CONFIG_PSCI_RESET) */

#ifdef CONFIG_PSCI_RESET
void reset_misc(void)
{
	do_psci_probe();
	invoke_psci_fn(PSCI_0_2_FN_SYSTEM_RESET, 0, 0, 0);
}
#endif /* CONFIG_PSCI_RESET */

#ifdef CONFIG_CMD_POWEROFF
int do_poweroff(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
	do_psci_probe();

	puts("poweroff ...\n");
	udelay(50000); /* wait 50 ms */

	disable_interrupts();
	invoke_psci_fn(PSCI_0_2_FN_SYSTEM_OFF, 0, 0, 0);
	enable_interrupts();

	log_err("Power off not supported on this platform\n");
	return CMD_RET_FAILURE;
}
#endif

static const struct udevice_id psci_of_match[] = {
	{ .compatible = "arm,psci" },
	{ .compatible = "arm,psci-0.2" },
	{ .compatible = "arm,psci-1.0" },
	{},
};

U_BOOT_DRIVER(psci) = {
	.name = DRIVER_NAME,
	.id = UCLASS_FIRMWARE,
	.of_match = psci_of_match,
	.bind = psci_bind,
	.probe = psci_probe,
};
