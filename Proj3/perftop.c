#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/sched.h>


/* Module information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Monami Dutta Gupta");
MODULE_DESCRIPTION("LKP Project 3");


/* declare a global counter variable */
static int counter = 0;

/*
 * set up kprobe information 
 */
#define MAX_SYMBOL_LEN 64
static char symbol[MAX_SYMBOL_LEN] = "perftop_open";
module_param_string(symbol, symbol, sizeof(symbol), 0644);

static char symbol2[MAX_SYMBOL_LEN] = "pick_next_task_fair";
module_param_string(symbol2, symbol2, sizeof(symbol2), 0644);

static struct kprobe kp = {
	.symbol_name = symbol
};


/*
 * Hash Table Implementation
 */

#define BITS 10
static DEFINE_HASHTABLE(tbl, BITS);

struct ht_entry {
	int pid;
        int data;
        struct hlist_node hashlist;
};


static int ht_store(int key)
{
	struct ht_entry *curr;
	int val = 0;
	struct ht_entry *my_entry = kmalloc(sizeof(*my_entry), GFP_ATOMIC);
	if(!my_entry || my_entry == NULL)
                return -ENOMEM;
	
	/*
	 * check for key, if it exists remove the entry and create new entry with incremented value
	 * cannot find any other way to do this
	 *
	 */
	hash_for_each_possible(tbl, curr, hashlist, key) {
		val = curr->data;
		hash_del(&curr->hashlist);
		kfree(curr);
	}
	
	my_entry->data = val + 1;
	my_entry->pid = key;
	hash_add(tbl, &my_entry->hashlist, key);
	return 0;
}

static void destroy_ht(void)
{
	struct ht_entry *curr_entry;
	int bkt;
 	struct hlist_node *next;
	printk(KERN_INFO "Deleting hash table!");
	hash_for_each_safe(tbl, bkt, next, curr_entry, hashlist){
		hash_del(&curr_entry->hashlist);
		kfree(curr_entry);
	}

}


/* 
 * kprobes pre handler implementation
 * kretprobe return handler implementation
 */


static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	++counter;
	return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) 
{
	
	int rc = 0;

	unsigned long retval = regs_return_value(regs);

	if(retval) {
        	struct task_struct *task = (struct task_struct *)(retval);
        	int pid = task->pid;

		rc = ht_store(pid);
        	if(rc)
			printk("error storing pid: %d\n", pid);
	}

	return rc;
}

static struct kretprobe my_kretprobe = {
	.handler = ret_handler,
	.kp.symbol_name = symbol2
};

/*
 * proc node implementation
 */

static int perftop_show(struct seq_file *m, void *v);
static int perftop_open(struct inode *inode, struct file *file);

static const struct proc_ops perftop_ops = {
	.proc_open = perftop_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release
};

static int perftop_show(struct seq_file *m, void *v)
{	
	int bkt;
	struct ht_entry *curr_entry;

	seq_printf(m, "Hello World!\n");
	seq_printf(m, "Counter value = %d\n", counter);

	/* print hash table entries */
        hash_for_each(tbl, bkt, curr_entry, hashlist)
                seq_printf(m, "key: %d and val: %d\n", curr_entry->pid, curr_entry->data);
	
	return 0;
}

static int perftop_open(struct inode *inode, struct file *file)
{
	return single_open(file, perftop_show, NULL);
}


/*
 * init and exit functions of module
 */
static int __init perftop_init(void)
{
	int ret;
	kp.pre_handler = handler_pre;
	
	/* create proc node */
	proc_create("perftop", 0, NULL, &perftop_ops);
	printk(KERN_INFO "/proc/perftop created!\n");
	
	/* register first kprobe */
	ret = register_kprobe(&kp);
	if(ret < 0) {
		printk(KERN_INFO "register kprobe failed, returned %d\n", ret);
		return ret;
	}
	printk(KERN_INFO "planted first kprobe at %p\n", kp.addr);
	


	/* register second kprobe */
	ret = register_kretprobe(&my_kretprobe);
        if(ret < 0) {
                printk(KERN_INFO "register kprobe failed, returned %d\n", ret);
                return ret;
        }
        printk(KERN_INFO "planted second kprobe at %p\n", my_kretprobe.kp.addr);

	return 0;
}

static void cleanup(void)
{
	/* unregistering the kprobes */
	unregister_kprobe(&kp);
        printk(KERN_INFO "first kprobe at %p unregistered\n", kp.addr);

        unregister_kretprobe(&my_kretprobe);
        printk(KERN_INFO "second kprobe at %p unregistered\n", my_kretprobe.kp.addr);

	/* cleaning hash table */
        destroy_ht();

	/* removing proc node */
        remove_proc_entry("perftop", NULL);
        printk(KERN_INFO "/proc/perftop removed!\n");
	return;
}

static void __exit perftop_exit(void)
{
	cleanup();
	return;
}

module_init(perftop_init);
module_exit(perftop_exit);
