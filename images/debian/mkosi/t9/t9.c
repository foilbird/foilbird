// T9: trivial test module, shipped unsigned / signed with our db key / signed with a foreign key (see mkosi.build).
#include <linux/module.h>
#include <linux/init.h>
static int __init t9_init(void) { pr_info("t9: module LOADED\n"); return 0; }
static void __exit t9_exit(void) { pr_info("t9: bye\n"); }
module_init(t9_init); module_exit(t9_exit);
MODULE_LICENSE("GPL"); MODULE_DESCRIPTION("T9 test module (Debian variant)");
