#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <linux/jhash.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>

#define BUFF_SIZE 1024
#define STACK_ENTRIES 4
#define BITS 10

/* Module information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Monami Dutta Gupta");
MODULE_DESCRIPTION("LKP Project 3");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef unsigned int (*stack_trace_save_user_t)(unsigned long *store, unsigned int size);

static kallsyms_lookup_name_t addr=NULL;


/*
 * set up kprobe information
 */
#define MAX_SYMBOL_LEN 64
static char symbol[MAX_SYMBOL_LEN] = "kallsyms_lookup_name";
module_param_string(symbol, symbol, sizeof(symbol), 0644);

static char symbol2[MAX_SYMBOL_LEN] = "pick_next_task_fair";
module_param_string(symbol2, symbol2, sizeof(symbol2), 0644);


/*
 * register kprobe for kallsyms
 *
 */


static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
        return 0;
}

static struct kprobe kp = {
        .pre_handler = handler_pre,
        .symbol_name = symbol
};

static kallsyms_lookup_name_t get_kallsyms_ptr(void)
{
        int ret;
        kallsyms_lookup_name_t addr;

        ret = register_kprobe(&kp);
        if(ret < 0) {
                printk(KERN_INFO "register kprobe failed, returned %d\n", ret);
                return NULL;
        }

        addr = (kallsyms_lookup_name_t) kp.addr;
        printk(KERN_INFO "planted first kprobe at %p\n", addr);
        return addr;
}

/*
 *
 * Red black tree implementation
 *
 */

static DEFINE_RAW_SPINLOCK(rb_lock);

struct rb_struct {
        unsigned long long time;
        unsigned long buff[BUFF_SIZE];
	int pid;
	u32 hash;
        struct rb_node node;
};

static struct rb_root rbtree = RB_ROOT;


static int cmp(unsigned long long time, struct rb_struct* b)
{
        int rc = 0;
        if(time > b->time)
                rc = 1;
        else if(time < b->time)
                rc = -1;

        return rc;
}

static void del_node(struct rb_node* curr)
{
	unsigned long flags;
        struct rb_struct *my_entry;
        my_entry = rb_entry(curr, struct rb_struct, node);
	raw_spin_lock_irqsave(&rb_lock, flags);
        if(my_entry){
                rb_erase(&my_entry->node, &rbtree);
                kfree(my_entry);
                printk(KERN_INFO "Deleted!\n");
        }
	raw_spin_unlock_irqrestore(&rb_lock, flags);
}

static void find_node(unsigned long long prev_task_time)
{
        int c;
        struct rb_node **link = &rbtree.rb_node;
        struct rb_node *parent = NULL;

        struct rb_struct *curr;

        while (*link) {
                parent = *link;
                curr = rb_entry(parent, struct rb_struct, node);

                c = cmp(prev_task_time, curr);
                if(c<0)
                        link = &parent->rb_left;
                else if(c>0)
                        link = &parent->rb_right;
                else {
                        printk(KERN_INFO "Found and handled!\n");
                        del_node(parent);
                        break;
                }
        }

}


static int store_rb(unsigned long long time, unsigned long* buff, int pid, u32 hash, int len, unsigned long long prev_task_time)
{
        unsigned long flags;
        int itr;
        struct rb_node **link;
        struct rb_node *parent;
        struct rb_struct *curr;
        struct rb_struct *my_entry;

	/* find node with old time, delete it */
	find_node(prev_task_time);

        my_entry = kmalloc(sizeof(*my_entry), GFP_ATOMIC);
        if(!my_entry || my_entry == NULL)
                return -ENOMEM;
        

	raw_spin_lock_irqsave(&rb_lock, flags);

        link = &rbtree.rb_node;
        parent = NULL;

        my_entry->time = time;
	my_entry->pid = pid;
	my_entry->hash = hash;
        for(itr=0; itr<len; itr++)
               my_entry->buff[itr] = buff[itr];
	  

        while(*link) {
                parent = *link;
                curr = rb_entry(parent, struct rb_struct, node);
                if(my_entry->time < curr->time)
                        link = &parent->rb_left;
                else
                        link = &parent->rb_right;
        }
	
	rb_link_node(&my_entry->node, parent, link);
	rb_insert_color(&my_entry->node, &rbtree);

	raw_spin_unlock_irqrestore(&rb_lock, flags);

        return 0;
}


static void destroy_rb(void)
{
	unsigned long flags;
        struct rb_node *curr;
        struct rb_struct *my_entry;

        printk(KERN_INFO "Deleting rb tree!\n");
	raw_spin_lock_irqsave(&rb_lock, flags);
        for(curr = rb_first(&rbtree); curr; curr = rb_next(curr)) {
                my_entry = rb_entry(curr, struct rb_struct, node);
                rb_erase(&my_entry->node, &rbtree);
                kfree(my_entry);
        }
	raw_spin_unlock_irqrestore(&rb_lock, flags);
}


/*
 *
 * Hash Table implementation
 *
 */

static DEFINE_RAW_SPINLOCK(hash_lock);
static DEFINE_HASHTABLE(tbl, BITS);

struct ht_entry {
	raw_spinlock_t lock;
	int data;
	int pid;
	unsigned long buff[BUFF_SIZE];
	unsigned long long curr_task_time;
	unsigned long long prev_task_time;
	struct hlist_node hashlist;
};

static unsigned long long store_ht(u32 key, int pid, unsigned long* buff, int len, unsigned long long time)
{
	unsigned long long prev_task_time = 12;
	struct ht_entry *curr;
	unsigned long flags;
	int val, itr;
	struct ht_entry *my_entry = kmalloc(sizeof(*my_entry), GFP_ATOMIC);

	if(!my_entry || !my_entry->buff)
		return -ENOMEM;

	raw_spin_lock_init(&my_entry->lock);

	/*
         * check for key, if it exists remove the entry and create new entry with incremented value
         * cannot find any other way to do this
         *
         */

        raw_spin_lock_irqsave(&hash_lock, flags);

	//delete previous entry from hash table
        hash_for_each_possible(tbl, curr, hashlist, key) {
                val = curr->data;
                hash_del(&curr->hashlist);
                kfree(curr);
        }
	if(val<1) {
		kfree(my_entry);
		raw_spin_unlock_irqrestore(&hash_lock, flags);
		return -1;
	}

        for(itr=0; itr<len; itr++){
                my_entry->buff[itr] = buff[itr];
       }
	
        my_entry->data = val + 1;
        my_entry->pid = pid;
        my_entry->prev_task_time = my_entry->curr_task_time;
        prev_task_time = my_entry->prev_task_time;
        my_entry->curr_task_time = time;


        //add current task to hash table
        hash_add(tbl, &my_entry->hashlist, key);

        raw_spin_unlock_irqrestore(&hash_lock, flags);

	return prev_task_time;
}


static void destroy_ht(void)
{
	unsigned long flags;
        struct ht_entry *curr_entry;
        int bkt;
        struct hlist_node *next;
        printk(KERN_INFO "Deleting hash table!");

	raw_spin_lock_irqsave(&hash_lock, flags);
        hash_for_each_safe(tbl, bkt, next, curr_entry, hashlist){
                hash_del(&curr_entry->hashlist);
                kfree(curr_entry);
        }
	raw_spin_unlock_irqrestore(&hash_lock, flags);
}


/* 
 * 
 * handle_stack() implementation
 * main function which which finds the stack trace and computes jhash.
 * calls ht_store() to store data in hash table
 * calls store_rb() to store data in rb tree.
 *
 */


static int handle_stack(int pid, int mode, unsigned long long time)
{
	int rc = 0, len = 0;
	stack_trace_save_user_t user_addr;
	u32 hash;
	unsigned int key_len;
	unsigned long *stack;
	unsigned long long prev_task_time;


        stack = kmalloc(BUFF_SIZE, GFP_ATOMIC);

        //kernel mode
        if(mode==0)
                len = stack_trace_save(stack, STACK_ENTRIES, 0);
        //user mode
        else {
                if(addr) {
                        user_addr =(stack_trace_save_user_t) addr("stack_trace_save_user");
                        if(user_addr)
                                len = user_addr(stack, STACK_ENTRIES);
                }
        }
        if(len==0){
                kfree(stack);
                return 0;
        }

        //compute jhash
        key_len = sizeof(stack[0])*len;
        hash = jhash((void*)stack, key_len, 0);

        //store in hash table
	prev_task_time = store_ht(hash, pid, stack, len, time);

        //store in rb-tree
        if(prev_task_time>0)
		rc = store_rb(time, stack, pid, hash, len, prev_task_time);
        if(rc)
                printk(KERN_INFO "error storing rb entry! \n");

        kfree(stack);
	
	return rc;
}

/*
 * Hash table to act as cache to store entry time and pid
 *
 */

static DEFINE_HASHTABLE(cache_tbl, BITS);
static DEFINE_RAW_SPINLOCK(cache_lock);

struct cache_entry {
        raw_spinlock_t lock;
        int pid; 
        unsigned long long entry_time;
        struct hlist_node hashlist;
};

static int cache_store(int key, unsigned long long time)
{
        unsigned long flags;
	
        struct cache_entry *my_entry = kmalloc(sizeof(*my_entry), GFP_ATOMIC);
        if(!my_entry || my_entry ==NULL)
                return -ENOMEM;

        raw_spin_lock_init(&my_entry->lock);
        raw_spin_lock_irqsave(&cache_lock, flags);

        my_entry->pid = key;
        my_entry->entry_time = time;
        hash_add(cache_tbl, &my_entry->hashlist, key);

        raw_spin_unlock_irqrestore(&cache_lock, flags);

        return 0;
}

static void cache_destroy(void)
{
	unsigned long flags;
        struct cache_entry *curr_entry;
        int bkt;
        struct hlist_node *next;
        printk(KERN_INFO "Deleting cache table!");
	raw_spin_lock_irqsave(&cache_lock, flags);
        hash_for_each_safe(cache_tbl, bkt, next, curr_entry, hashlist){
                hash_del(&curr_entry->hashlist);
                kfree(curr_entry);
        }
	raw_spin_unlock_irqrestore(&cache_lock, flags);
}


/*
 * kretprobe entry and return handlers
 *
 */

static DEFINE_RAW_SPINLOCK(entry_lock);

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        int rc = 0;
        int pid;
        unsigned long long start_time;
        unsigned long flags;

        raw_spin_lock_irqsave(&entry_lock, flags);
        pid = current->pid;
        start_time = rdtsc();
        raw_spin_unlock_irqrestore(&entry_lock, flags);

        rc = cache_store(pid, start_time);
        if(rc)
                printk(KERN_INFO "error in cache!\n");

        return 0;
}


static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int rc = 0;
	unsigned long retval;
	unsigned long long start_time, total_time;
	int pid;
	struct cache_entry *curr;
	struct task_struct *task;
	struct mm_struct *mm;


	retval = regs_return_value(regs);
	if(retval) {

		task = (struct task_struct *)retval;
		task = list_entry(task->tasks.prev, struct task_struct, tasks);

		pid = task->pid;

		hash_for_each_possible(cache_tbl, curr, hashlist, pid)
			start_time = curr->entry_time;
			
		total_time = rdtsc() - start_time;
		mm = (struct mm_struct *)task->mm;

		if(pid!=0){
			if(mm==NULL)
				rc = handle_stack(pid, 0, total_time);
			else
				rc = handle_stack(pid, 1, total_time);
			if(rc)
				printk(KERN_INFO "error in handle_stack function!\n");
		}
	}

	return rc;
}



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
	struct rb_node *curr;
        struct rb_struct *my_entry;
        int i = 1, itr;
	char *buff = kmalloc(BUFF_SIZE, GFP_ATOMIC);

	/* print rb tree entries */
        for(curr = rb_last(&rbtree); curr && i<=20; curr = rb_prev(curr)) {
                my_entry = rb_entry(curr, struct rb_struct, node);
                seq_printf(m, "\n\nRank: %d\n", i);
		seq_printf(m, "Pid: %d and JHash: %u\n", my_entry->pid, my_entry->hash);
		seq_printf(m, "\ntime spent by task: %llu rdtsc ticks.\n\n", my_entry->time);
                seq_printf(m, "Stack trace: \n");
                for(itr = 0; itr<STACK_ENTRIES; itr++)
			if(my_entry->buff[itr])
				seq_printf(m, "0x%lx\n", my_entry->buff[itr]);

		seq_printf(m, "\nFunction names: \n");
		for(itr = 0; itr<STACK_ENTRIES; itr++)
                        if(my_entry->buff[itr]){
				sprint_symbol(buff, my_entry->buff[itr]);
                                seq_printf(m, "%s\n", buff);
			}
                ++i;
        }
	kfree(buff);

        return 0;
}

static int perftop_open(struct inode *inode, struct file *file)
{
        return single_open(file, perftop_show, NULL);
}



/*
 *
 * Register kretprobe for pick_next_task_fair
 *
 */

static struct kretprobe my_kretprobe = {
        .handler = ret_handler,
        .kp.symbol_name = symbol2,
        .entry_handler = entry_handler
};

static int set_kretprobe(void)
{
        int ret = 0;
        ret = register_kretprobe(&my_kretprobe);
        if(ret < 0) {
                printk(KERN_INFO "register kretprobe failed, returned %d\n", ret);
                return ret;
        }
        printk(KERN_INFO "planted kretprobe at %p\n", my_kretprobe.kp.addr);

        return ret;
}


/*
 * init and exit functions of module
 */
static int __init perftop_init(void)
{
        int ret = 0;
        /* create proc node */
        proc_create("perftop", 0, NULL, &perftop_ops);
        printk(KERN_INFO "/proc/perftop created!\n");

        /* call kallsyms lookup ptr function */
        addr = get_kallsyms_ptr();


        /* register kretprobe */
        ret = set_kretprobe();

        return 0;
}

static void cleanup(void)
{
        /* unregistering the kprobes */
        unregister_kprobe(&kp);
        printk(KERN_INFO "first kprobe at %p unregistered\n", kp.addr);

        unregister_kretprobe(&my_kretprobe);
        printk(KERN_INFO "second kprobe at %p unregistered\n", my_kretprobe.kp.addr);

        /*cleaning cache table */
        cache_destroy();

        /* cleaning hash table */
        destroy_ht();

        /* cleaning rb tree*/
        destroy_rb();

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

