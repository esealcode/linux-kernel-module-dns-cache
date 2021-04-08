#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x44abaccb, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x4aad7d72, __VMLINUX_SYMBOL_STR(nf_unregister_hook) },
	{ 0xdf208201, __VMLINUX_SYMBOL_STR(nf_register_hook) },
	{ 0x114d0f9a, __VMLINUX_SYMBOL_STR(skb_push) },
	{ 0x4a619f83, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x6c2e3320, __VMLINUX_SYMBOL_STR(strncmp) },
	{ 0x125093c, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0x1a05e1b0, __VMLINUX_SYMBOL_STR(_raw_read_lock) },
	{ 0xa325055e, __VMLINUX_SYMBOL_STR(dev_base_lock) },
	{ 0x57fcd8ab, __VMLINUX_SYMBOL_STR(netif_rx) },
	{ 0x50eedeb8, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xb4390f9a, __VMLINUX_SYMBOL_STR(mcount) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "B61FCD90FBBA3A2D60F3F11");
