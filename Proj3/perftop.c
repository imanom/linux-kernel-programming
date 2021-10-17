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

/* Module information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Monami Dutta Gupta");
MODULE_DESCRIPTION("LKP Project 3");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef unsigned int (*stack_trace_save_user_t)(unsigned long *store, unsigned int size);

static kallsyms_lookup_name_t addr=NULL;
static DEFINE_RAW_SPINLOCK(hash_lock);
static DEFINE_RAW_SPINLOCK(rb_lock);
static DEFINE_RAW_SPINLOCK(main_lock);



/*
 * set up kprobe information 
 */
#define MAX_SYMBOL_LEN 64
static char symbol[MAX_SYMBOL_LEN] = "kallsyms_lookup_name";
module_param_string(symbol, symbol, sizeof(symbol), 0644);

static char symbol2[MAX_SYMBOL_LEN] = "pick_next_task_fair";
module_param_string(symbol2, symbol2, sizeof(symbol2), 0644);


/*
 * kallsyms 
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
 * Red black tree Implementation
 *
 */

struct rb_struct {
	unsigned long long time;
	unsigned long buff[1024];
	struct rb_node node;
};

struct rb_root rbtree = RB_ROOT;

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
	struct rb_struct *my_entry;
	my_entry = rb_entry(curr, struct rb_struct, node);
	rb_erase(&my_entry->node, &rbtree);
	kfree(my_entry);

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
                        del_node(parent);
                        break;
                }
        }
}

static int store_rb(unsigned long long time, unsigned long* buff, int len, unsigned long long prev_task_time)
{
	unsigned long flags;
	int itr = 0;
	struct rb_node **link = &rbtree.rb_node;
	struct rb_node *parent = NULL;
	struct rb_struct *curr;
	struct rb_struct *my_entry = kmalloc(sizeof(my_entry), GFP_ATOMIC);
	if(!my_entry || my_entry == NULL)
		return -ENOMEM;

//	find_node(prev_task_time);

	raw_spin_lock_irqsave(&rb_lock, flags);

	my_entry->time = time;
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
	struct rb_node *curr;
	struct rb_struct *my_entry;

	printk(KERN_INFO "Deleting rb tree!\n");

	for(curr = rb_first(&rbtree); curr; curr = rb_next(curr)) {
		my_entry = rb_entry(curr, struct rb_struct, node);
		rb_erase(&my_entry->node, &rbtree);
		kfree(my_entry);
	}
}

/*
 *
 * Hash Table Implementation
 *
 */

#define BITS 10
static DEFINE_HASHTABLE(tbl, BITS);

struct ht_entry {
	raw_spinlock_t lock;
        int data;
	int pid;
	unsigned long buff[1024];
	unsigned long long curr_task_time;
	unsigned long long prev_task_time;
        struct hlist_node hashlist;
};


static unsigned long long ht_store(u32 key,int pid, unsigned long* buff,int len, unsigned long long time)
{
	struct ht_entry *curr;
	unsigned long flags;
	int val;
	int itr;
	unsigned long long prev_task_time;
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

	for(itr=0; itr<len; itr++)
		my_entry->buff[itr] = buff[itr];

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
	struct cache_entry *curr;
	unsigned long flags;
	int val = 0;
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
	struct cache_entry *curr_entry;
	int bkt;
 	struct hlist_node *next;
	printk(KERN_INFO "Deleting cache table!");
	hash_for_each_safe(cache_tbl, bkt, next, curr_entry, hashlist){
		hash_del(&curr_entry->hashlist);
		kfree(curr_entry);
	}

}

/* 
 * 
 * kretprobe return handler implementation
 */

static DEFINE_RAW_SPINLOCK(kernel_lock);
static DEFINE_RAW_SPINLOCK(user_lock);

static int handle_stack(int pid, int mode, unsigned long long time)
{
	int rc = 0;
	int len = 0;
	stack_trace_save_user_t user_addr;
	u32 hash;
	unsigned int key_len;
	unsigned long flags, flags2;
	unsigned long *stack;
	unsigned long long prev_task_time;


	//kernel task	
	if(mode == 0) {
		raw_spin_lock_irqsave(&kernel_lock, flags);
		stack = kmalloc(1024, GFP_ATOMIC);
		len = stack_trace_save(stack, 6, 0);
		if(len==0){
			raw_spin_unlock_irqrestore(&kernel_lock, flags);
			return 0;
		}
		key_len = sizeof(stack[0])*len;
		hash = jhash((void*)stack, key_len, 0);
		raw_spin_unlock_irqrestore(&kernel_lock, flags);
		

	}

	//user task
	else {
		if(addr) {
			user_addr =(stack_trace_save_user_t) addr("stack_trace_save_user");
			if(user_addr){
				raw_spin_lock_irqsave(&user_lock, flags2);
				stack = kmalloc(1024, GFP_ATOMIC);
				len = user_addr(stack, 6);
				if(len==0){
					raw_spin_unlock_irqrestore(&user_lock, flags2);
					return 0;
				}
				key_len = sizeof(stack[0])*len;
				hash = jhash((void*)stack, key_len, 0);
				raw_spin_unlock_irqrestore(&user_lock, flags2);
				
			}
		}

	}


	
	prev_task_time = ht_store(hash, pid, stack, len, time);

//	if(prev_task_time>0)	
//		rc = store_rb(time, stack, len, prev_task_time);
	if(rc)
               printk(KERN_INFO "error storing rb entry! \n");
	
	
	kfree(stack);

	return rc;
}

static DEFINE_RAW_SPINLOCK(entry_lock);

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int rc = 0;
	int pid;
        unsigned long long start_time;
	unsigned long flags;
	
	raw_spin_lock_irqsave(&entry_lock, flags);
	pid = current ->pid;
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
	unsigned long flags, retval;
	unsigned long long start_time, time;
	int pid;
	struct mm_struct *mm;
	struct task_struct *task;
	struct cache_entry *curr;

	
	retval = regs_return_value(regs);
	
	if(retval) {
		raw_spin_lock_irqsave(&main_lock, flags);

        	task = (struct task_struct *)(retval);
		task = list_entry(task->tasks.prev, struct task_struct, tasks);
		
       		pid = task->pid;


		// fetch start time from cached entry 
		hash_for_each_possible(cache_tbl, curr, hashlist, pid) 
			start_time = curr->entry_time;

		time = rdtsc() - start_time;
		mm = (struct mm_struct *) task->mm; 

		raw_spin_unlock_irqrestore(&main_lock, flags);

		if(pid!=0){
			if(mm == NULL)	//check if mm ptr is NULL.
				rc = handle_stack(pid, 0, time); //kernel space
			else
				rc = handle_stack(pid, 1, time); //user space

       			if(rc)
				printk(KERN_INFO "error in handle_stack function!\n");		
		}
		

	}

	return 0;
}

static struct kretprobe my_kretprobe = {
	.handler = ret_handler,
	.kp.symbol_name = symbol2,
	.entry_handler = entry_handler
};

static int set_probe_2(void)
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
	//struct rb_node *curr;
	//struct rb_struct *my_entry;
	//int i = 0;
	int itr = 0;

	/* print hash table entries */
        hash_for_each(tbl, bkt, curr_entry, hashlist){
		seq_printf(m, "\npid: %d and count: %d\n", curr_entry->pid, curr_entry->data);
		seq_printf(m, "stack trace: \n");
		for(itr = 0; itr<4; itr++)
			if(curr_entry->buff[itr])
                		seq_printf(m, "0x%lx\n", curr_entry->buff[itr]);
		seq_printf(m, "time spent by task: %llu \n\n\n", curr_entry->curr_task_time);
	}


	/* print rb tree entries */
/*	for(curr = rb_first(&rbtree); curr && i<20; curr = rb_next(curr)) {
		my_entry = rb_entry(curr, struct rb_struct, node);
		seq_printf(m, "COUNT: %d\n\n", i);
		seq_printf(m, "stack trace: \n");
                for(itr2 = 0; itr2<4; itr2++)
                        if(my_entry->buff[itr2])
                                seq_printf(m, "0x%lx\n", my_entry->buff[itr2]);
                seq_printf(m, "time spent by task: %llu \n\n\n", my_entry->time);

	//	seq_printf(m, "stack trace: %s\n", (char*)my_entry->buff);
	//	seq_printf(m, "time spent by task: %llu \n\n\n", my_entry->time);
		++i;
	}
*/
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
	int ret = 0;
	/* create proc node */
	proc_create("perftop", 0, NULL, &perftop_ops);
	printk(KERN_INFO "/proc/perftop created!\n");

	/* call kallsyms lookup ptr function */
	addr = get_kallsyms_ptr();
	

	/* register kretprobe */
	ret = set_probe_2();

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
