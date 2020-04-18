// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2020 Linaro Limited
 */

#include <common.h>
#include <dm.h>
#include <efi_loader.h>
#include <dm/of.h>
#include <dm/of_access.h>
#include <linux/arm-smccc.h>
#include <linux/compat.h>
#include <linux/kconfig.h>
#include <linux/printk.h>

/*
 * Set __efi_runtime_data attribute to support EFI runtime context.
 * arm_smccc_1_0_invoke() must only rely on this EFI runtime variable.
 */
#if CONFIG_IS_ENABLED(EFI_LOADER)
static enum arm_smccc_conduit arm_smccc_conduit __efi_runtime_data;
#else
static enum arm_smccc_conduit arm_smccc_conduit
__attribute__ ((section (".data")));
#endif

static const char *conduit_str(enum arm_smccc_conduit conduit)
{
	switch (conduit) {
	case SMCCC_CONDUIT_HVC:
		return "hvc";
	case SMCCC_CONDUIT_SMC:
		return "smc";
	default:
		return "invalid";
	}
}

static enum arm_smccc_conduit method_to_conduit(const char *dev_name,
						const char *method)
{
	if (!strcmp("hvc", method))
		return SMCCC_CONDUIT_HVC;

	if (!strcmp("smc", method))
		return SMCCC_CONDUIT_SMC;

	pr_err("%s: invalid \"method\" property \"%s\"\n", dev_name, method);

	return SMCCC_CONDUIT_NONE;
}

static bool find_conduit_method_from_named_device(const char *dev_name)
{
	struct udevice *dev;
	const char *method;

	if (!uclass_get_device_by_name(UCLASS_FIRMWARE, dev_name, &dev)) {
		method = ofnode_get_property(dev->node, "method", NULL);
		if (method)
			arm_smccc_conduit = method_to_conduit(dev_name, method);
	}

	return arm_smccc_conduit != SMCCC_CONDUIT_NONE;
}

static void set_generic_conduit(void)
{
	/* Parse only once the DT for a generic config */
	if (arm_smccc_conduit != SMCCC_CONDUIT_RESET)
		return;

	arm_smccc_conduit = SMCCC_CONDUIT_NONE;

	if (IS_ENABLED(CONFIG_ARM_PSCI_FW) &&
	    find_conduit_method_from_named_device("psci"))
		return;

	if (IS_ENABLED(CONFIG_OPTEE) &&
	    find_conduit_method_from_named_device("optee"))
		return;

	pr_err("No generic SMCCC conduit method found\n");
}

int devm_arm_smccc_1_0_set_conduit(struct udevice *dev, const char *prop)
{
	enum arm_smccc_conduit dev_conduit = SMCCC_CONDUIT_NONE;
	const char *method = NULL;

	if (dev && prop)
		method = ofnode_get_property(dev->node, prop, NULL);

	if (method) {
		dev_conduit = method_to_conduit(dev->name, method);

		if (dev_conduit == SMCCC_CONDUIT_NONE)
			return -EINVAL;

		if (arm_smccc_conduit <= SMCCC_CONDUIT_NONE) {
			arm_smccc_conduit = dev_conduit;
			return 0;
		}

		if (dev_conduit == arm_smccc_conduit)
			return 0;

		dev_err(dev, "inconsistent conduits %u/%s vs %u/%s\n",
			dev_conduit, conduit_str(dev_conduit),
			arm_smccc_conduit, conduit_str(arm_smccc_conduit));

		return -EINVAL;
	}

	/*
	 * No device specified and/or no method found, look up in generic
	 * devices for a conduit method.
	 */
	set_generic_conduit();

	if (arm_smccc_conduit != SMCCC_CONDUIT_NONE)
		return 0;

	dev_err(dev, "missing \"method\" property\n");

	return -ENXIO;
}

/* Set __efi_runtime attribute to allow support EFI runtime context */
enum arm_smccc_conduit __efi_runtime
arm_smccc_1_0_invoke(unsigned long a0, unsigned long a1, unsigned long a2,
		     unsigned long a3, unsigned long a4, unsigned long a5,
		     unsigned long a6, unsigned long a7,
		     struct arm_smccc_res *res)
{
	/*
	 * In the __efi_runtime we need to avoid the switch statement. In some
	 * cases the compiler creates lookup tables to implement switch. These
	 * tables are not correctly relocated when SetVirtualAddressMap is
	 * called.
	 */
	if (arm_smccc_conduit == SMCCC_CONDUIT_HVC) {
		arm_smccc_hvc(a0, a1, a2, a3, a4, a5, a6, a7, res);
	} else if (arm_smccc_conduit == SMCCC_CONDUIT_SMC) {
		arm_smccc_smc(a0, a1, a2, a3, a4, a5, a6, a7, res);
	} else {
		res->a0 = SMCCC_RET_NOT_SUPPORTED;
		return SMCCC_CONDUIT_NONE;
	}

	return arm_smccc_conduit;
}
