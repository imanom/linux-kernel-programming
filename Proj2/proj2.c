#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/xarray.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>


static char *int_str;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Monami Dutta Gupta");
MODULE_DESCRIPTION("LKP Project 2");


module_param(int_str, charp, S_IRUSR | S_IRGRP | S_IROTH);

MODULE_PARM_DESC(int_str, "A comma-separated list of integers");

/*
 * Linked list implementation - same as Exercise 3
 */

static LIST_HEAD(mylist);

struct entry {
	int val;
	struct list_head list;
};


static int store_value(int val)
{
	struct entry *my_entry = kmalloc(sizeof(*my_entry), GFP_KERNEL);
	if(!my_entry || my_entry == NULL)
		return -ENOMEM;
	my_entry->val = val;
	INIT_LIST_HEAD(&my_entry->list);

	list_add_tail(&my_entry->list, &mylist);	
	return 0;	
}

static void test_linked_list(void)
{
	struct entry *curr_entry;
	printk(KERN_INFO"Linked list: ");
	list_for_each_entry(curr_entry, &mylist, list) {
		printk(KERN_CONT "%d ", curr_entry->val);
	}

}


static void destroy_linked_list_and_free(void)
{
	struct entry *curr_entry, *next;
	printk(KERN_INFO"Deleting linked list: ");
	list_for_each_entry_safe(curr_entry, next, &mylist, list){
		printk(KERN_CONT "%d ", curr_entry->val);
		list_del(&curr_entry->list);
		kfree(curr_entry);
	}

}


/*
 * Hash Table Implementation
 */

#define BITS 10
static DEFINE_HASHTABLE(tbl, BITS);

struct ht_entry {
        int data;
        struct hlist_node hashlist;
};


static int ht_store_val(int val)
{
	struct ht_entry *my_entry = kmalloc(sizeof(*my_entry), GFP_KERNEL);
	if(!my_entry || my_entry == NULL)
                return -ENOMEM;
        my_entry->data = val;
	hash_add(tbl, &my_entry->hashlist, val);
	return 0;
}

static void test_ht(void)
{
	struct ht_entry *curr_entry;
	int bkt;
	printk(KERN_INFO"Hash table: ");
	hash_for_each(tbl, bkt, curr_entry, hashlist) 
		printk(KERN_CONT "%d ", curr_entry->data);

}

static void destroy_ht(void)
{
	struct ht_entry *curr_entry;
	int bkt;
 	struct hlist_node *next;
	printk(KERN_INFO "Deleting hash table: ");
	hash_for_each_safe(tbl, bkt, next, curr_entry, hashlist){
		printk(KERN_CONT "%d ", curr_entry->data);
		hash_del(&curr_entry->hashlist);
		kfree(curr_entry);
	}

}



/* 
 * Red black tree implementation
 */

struct mynode {
	int data;
	struct rb_node node;
};

struct rb_root rbtree = RB_ROOT;

static int store_rb(int val)
{
	struct rb_node **link = &rbtree.rb_node;
        struct rb_node *parent=NULL;
        struct mynode *curr;
	struct mynode *my_entry = kmalloc(sizeof(my_entry), GFP_KERNEL);
	if(!my_entry || my_entry == NULL)
                return -ENOMEM;
        my_entry->data = val;

	while(*link) {
		parent = *link;
		curr = rb_entry(parent, struct mynode, node);
		if(my_entry->data < curr->data)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}

	// Insert new node and rebalance tree
	 
	rb_link_node(&my_entry->node, parent, link);
	rb_insert_color(&my_entry->node, &rbtree);
	return 0;
}

static void test_rb(void)
{
	struct rb_node *curr;
	struct mynode *my_entry;
	printk(KERN_INFO "Red-black tree: ");
	for(curr = rb_first(&rbtree); curr; curr = rb_next(curr)) {
		my_entry = rb_entry(curr, struct mynode, node);
		printk(KERN_CONT "%d ", my_entry->data);
	}

}

static void destroy_rb(void)
{
	struct rb_node *curr;
	struct mynode *my_entry;
	printk(KERN_INFO "Deleting Red-black tree: ");
	for(curr = rb_first(&rbtree); curr; curr = rb_next(curr)) {
		my_entry = rb_entry(curr, struct mynode, node);
		printk(KERN_CONT "%d ", my_entry->data);
		rb_erase(&my_entry->node, &rbtree);
		kfree(my_entry);
	}

}

/*
 * Radix tree implementation
 */

static RADIX_TREE(my_tree, GFP_KERNEL);

struct radix_entry {
	int data;
	struct radix_tree_root tree;
};

static int store_radix(int val)
{
	int rc;
	struct radix_entry *my_entry = kmalloc(sizeof(my_entry), GFP_KERNEL);
        if(!my_entry || my_entry == NULL)
                return -ENOMEM;
        my_entry->data = val;
	
	rc = radix_tree_preload(GFP_KERNEL);
	if(rc)
		return rc;

	rc = radix_tree_insert(&my_tree, (unsigned long)val, my_entry);

	radix_tree_preload_end();
	return rc;
}

static void test_radix(void)
{
	unsigned long first_index=0;
	struct radix_entry *results[10];
	unsigned int max_items = 10;
	int i;
	int items = radix_tree_gang_lookup(&my_tree, (void**)results, first_index, max_items);
	printk(KERN_INFO "Radix tree: ");
	for(i=0; i<items; i++) {
		printk(KERN_CONT "%d ", results[i]->data);
	}

}

static void destroy_radix(void)
{
	struct radix_entry  *results[10];
        unsigned long pos=0;
        unsigned int max_items = 10;
	void *ret;
	int i;
	int items = radix_tree_gang_lookup(&my_tree, (void**)results, pos, max_items);
       	printk(KERN_INFO "Deleting Radix tree: ");
	for(i=0; i<items; i++) {
        	printk(KERN_CONT "%d ", results[i]->data);		
		ret = radix_tree_delete(&my_tree,(unsigned long) results[i]->data);
	       	if(ret)
			kfree(ret);	
        }
}

/*
 * XArray implementation
 */

static DEFINE_XARRAY(my_array);

struct xarray_entry {
	int data;
	struct xarray arr;
};



static int store_xarray(int val)
{
	
        struct xarray_entry *my_entry = kmalloc(sizeof(my_entry), GFP_KERNEL);
        if(!my_entry || my_entry == NULL)
                return -ENOMEM;
        my_entry->data = val;
	
	xa_store(&my_array, (unsigned long)val, my_entry, GFP_KERNEL);
	return 0;
}

static void test_xarray(void)
{
	struct xarray_entry *my_entry;
	unsigned long index;
	printk(KERN_INFO "Xarray: ");
	xa_for_each(&my_array, index, my_entry) {
		printk(KERN_CONT"%d ", my_entry->data);
	}
}

static void destroy_xarray(void)
{
	struct xarray_entry *my_entry;
	unsigned long index;
	printk(KERN_INFO "Deleting Xarray: ");
	xa_for_each(&my_array, index, my_entry) {
		printk(KERN_CONT "%d ", my_entry->data);
		xa_erase(&my_array, index);
		kfree(my_entry);
	}
}



/*
 * Proc fs implementation
 */
static int proj2_show(struct seq_file *m, void *v);
static int proj2_open(struct inode *inode, struct file *file);

static const struct proc_ops proj2_ops = {
	.proc_open = proj2_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int proj2_show(struct seq_file *m, void *v)
{
	struct entry *entry_linkedlist;
	int bkt;
	struct ht_entry *entry_ht;
	struct rb_node *curr;
        struct mynode *entry_rb;
	unsigned long first_index=0;
        struct radix_entry *results[10];
        unsigned int max_items = 10;
        int i, items;
	struct xarray_entry *entry_xa;
        unsigned long index;

        //Linked List
	seq_printf(m, "Linked list: ");
        list_for_each_entry(entry_linkedlist, &mylist, list) {
                seq_printf(m, "%d ", entry_linkedlist->val);
        }	
	seq_printf(m,"\n");

	//hash table
        seq_printf(m, "Hash table: ");
        hash_for_each(tbl, bkt, entry_ht, hashlist)
                seq_printf(m, "%d ", entry_ht->data);
	seq_printf(m,"\n");
        

	//red black tree
        seq_printf(m, "Red-black tree: ");
        for(curr = rb_first(&rbtree); curr; curr = rb_next(curr)) {
                entry_rb = rb_entry(curr, struct mynode, node);
                seq_printf(m, "%d ", entry_rb->data);
        }
	seq_printf(m,"\n");	

	//radix tree
	items = radix_tree_gang_lookup(&my_tree, (void**)results, first_index, max_items);
        seq_printf(m, "Radix tree: ");
        for(i=0; i<items; i++) {
                seq_printf(m, "%d ", results[i]->data);
        }
	seq_printf(m,"\n");

	//xarray
        seq_printf(m, "Xarray: ");
        xa_for_each(&my_array, index, entry_xa) {
                seq_printf(m, "%d ", entry_xa->data);
        }
	seq_printf(m,"\n");


	return 0;
}

static int proj2_open(struct inode *inode, struct file *file)
{
	return single_open(file, proj2_show, NULL);
}


static int parse_params(void)
{
	int val, err = 0;
	char *p, *orig, *params;

	params = kstrdup(int_str, GFP_KERNEL);
	if (!params)
		return -ENOMEM;
	orig = params;

	while ((p = strsep(&params, ",")) != NULL) {
		if (!*p)
			continue;
		err = kstrtoint(p, 0, &val);
		if (err)
			break;
		err = store_value(val);
		if (err)
			break;
		err = ht_store_val(val);
		if(err)
			break;
		err = store_rb(val);
		if(err)
			break;

		err = store_radix(val);
		if(err)
			break;

		err = store_xarray(val);
		if(err)
			break;
	}


	kfree(orig);
	return err;
}

static void run_tests(void)
{
	test_linked_list();
	test_ht();
	test_rb();
	test_radix();
	test_xarray();

}

static void cleanup(void)
{
	printk(KERN_INFO "\nCleaning up...\n");

	destroy_linked_list_and_free();
	destroy_ht();
	destroy_rb();
	destroy_radix();
	destroy_xarray();

}

static int __init proj2_init(void)
{
	int err = 0;

	if (!int_str) {
		printk(KERN_INFO "Missing \'int_str\' parameter, exiting\n");
		return -1;
	}

	err = parse_params();
	if (err)
		goto out;

	run_tests();
	proc_create("proj2", 0, NULL, &proj2_ops);
	printk(KERN_INFO "/proc/proj2 created\n");
out:
	return err;
}

static void __exit proj2_exit(void)
{
	cleanup();
	printk("Cleanup finished!\n");
	remove_proc_entry("proj2", NULL);
	printk(KERN_INFO "/proc/proj2 removed\n");
	return;
}

module_init(proj2_init);

module_exit(proj2_exit);
