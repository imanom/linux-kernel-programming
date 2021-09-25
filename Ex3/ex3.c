#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

static char *int_str;

/* [X1: point 1]
 * When creating a loadable kernel module we need to provide module information.
 * MODULE_LICENSE - Allows the module to declare their license. Helps developers know when a non-free license has been inserted into the kernel.
 * MODULE AUTHOR - Author of the module
 * MODULE_DESCRIPTION - description of the module
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Monami Dutta Gupta");
MODULE_DESCRIPTION("LKP Exercise 4");

/* [X2: point 1]
 * Explain following in here.
 * To allow arguments to be passed into a kernel module, we have to declare our variable which will take the command line argument as global. For example, int_str in our case.
 * And then we need to pass certain parameters into the module_param function.
 * First parameter - name of the variable
 * Second parameter - type of the variable, charp=char pointer.
 * Third parameter - permission bits. (S_IRUSR = User read permission, S_IRGRP = Group read permission, S_IROTH = Others read permission)
 */
module_param(int_str, charp, S_IRUSR | S_IRGRP | S_IROTH);

/* [X3: point 1]
 * Explain following in here.
 * MODULE_PARM_DESC() is a macro function that documents arguments that the module can take. 
 * First parameter - variable name
 * Second parameter - String describing the parameter.
 */
MODULE_PARM_DESC(int_str, "A comma-separated list of integers");

/* [X4: point 1]
 * Explain following in here.
 * LIST_HEAD is a macro which defines and initializes a struct list_head whose name is passed as argument.
 * Creating a list called mylist which will have next and prev pointers pointing to itself.
 * It is the head node of the list. Subsequent new nodes can be added to the list using list_add or list_add_tail.
 */
static LIST_HEAD(mylist);

/* [X5: point 1]
 * entry is a structure containing two members - one integer variable and a list_head struct.
 * The struct list_head is used in kernel linked lists to contain references to the previous and next nodes of the current node.
 */
struct entry {
	int val;
	struct list_head list;
};

static int store_value(int val)
{
	/* [X6: point 10]
	 * Allocate a struct entry of which val is val
	 * and add it to the tail of mylist.
	 * Return 0 if everything is successful.
	 * Otherwise (e.g., memory allocation failure),
	 * return corresponding error code in error.h (e.g., -ENOMEM).
	 */
	
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
	/* [X7: point 10]
	 * Print out value of all entries in mylist.
	 */
	struct entry *curr_entry;

	list_for_each_entry(curr_entry, &mylist, list) {
		printk(KERN_INFO "Val: %d\n", curr_entry->val);
	}

}


static void destroy_linked_list_and_free(void)
{
	/* [X8: point 10]
	 * Free all entries in mylist.
	 */
	struct entry *curr_entry, *next;
	list_for_each_entry_safe(curr_entry, next, &mylist, list){
		printk(KERN_INFO "Val to be deleted: %d\n", curr_entry->val);
		list_del(&curr_entry->list);
		kfree(curr_entry);
	}
}


static int parse_params(void)
{
	int val, err = 0;
	char *p, *orig, *params;


	/* [X9: point 1]
	 * Explain following in here.
	 * kstrdup is used to allocate space for and copy an existing string.
	 * First parameter - name of the string to duplicate.
	 * Second parameter - The GFP mask used in the kmalloc call when allocating space for the string.
	 */
	params = kstrdup(int_str, GFP_KERNEL);
	if (!params)
		return -ENOMEM;
	orig = params;

	/* [X10: point 1]
	 * strsep() is used to parse a string into tokens using a delimeter, "," in our case.
	 * The while loop iterates over the string and sets p to a token. The loop breaks when we execute the last token and it returns NULL.
	 */
	while ((p = strsep(&params, ",")) != NULL) {
		if (!*p)
			continue;
		/* [X11: point 1]
		 * Explain following in here.
		 * kstrtoint() converts a string to an integer.
		 * First parameter - the name of the string
		 * Second parameter - the number base to use. If given as 0, the number base will be auto detected based on the semantics.
		 * Third parameter - where to write the result of conversion if it is a success.
		 *
		 * Returns 0 on success, so if the return code is not 0 then we must break.
		 */
		err = kstrtoint(p, 0, &val);
		if (err)
			break;

		/* [X12: point 1]
		 * Explain following in here.
		 * On successful conversion of string to integer, the value now has to be stored in the structure we defines in the function store_value().
		 * We are returning 0 on success, so error code must be checked again for errors such as -ENOMEM.
		 */
		err = store_value(val);
		if (err)
			break;
	}

	/* [X13: point 1]
	 * Explain following in here.
	 * kfree() deallocates the memory for the orig pointer since the computation is finished and we no longer need them.
	 */
	kfree(orig);
	return err;
}

static void run_tests(void)
{
	/* [X14: point 1]
	 * Explain following in here.
	 * We test the values were actually inserted into the linked list by iterating over the list and printing the values in the kernel log.
	 * 
	 */
	test_linked_list();
}

static void cleanup(void)
{
	/* [X15: point 1]
	 * Explain following in here.
	 * This funstion deletes all the entries in the linked list and frees up the allocated memory.
	 */
	printk(KERN_INFO "\nCleaning up...\n");

	destroy_linked_list_and_free();
}

static int __init ex3_init(void)
{
	int err = 0;

	/* [X16: point 1]
	 * Explain following in here.
	 * If no command line argument is provided while running the module, throw an error message and exit.
	 */
	if (!int_str) {
		printk(KERN_INFO "Missing \'int_str\' parameter, exiting\n");
		return -1;
	}

	/* [X17: point 1]
	 * Explain following in here.
	 * The parse_params() function is a user defined function to parse the init_str parameter and store the values in the structure. 
	 */
	err = parse_params();
	if (err)
		goto out;

	/* [X18: point 1]
	 * Explain following in here.
	 * Calls the user defined function to print values stored in the structure.
	 */
	run_tests();
out:
	/* [X19: point 1]
	 * Explain following in here.
	 * After printing, calls the cleanup() function which deletes the values and frees up the allocated memory.
	 */
	cleanup();
	return err;
}

static void __exit ex3_exit(void)
{
	/* [X20: point 1]
	 * Explain following in here.
	 * Functions with the __exit identifier are called when the module is exiting. 
	 * Tells the kernel that the module has exited and all the address space, etc used by it can be reclaimed.
	 */
	return;
}

/* [X21: point 1]
 * Explain following in here.
 * module_init() macro defines which function has to be called during module insertion time.
 */
module_init(ex3_init);

/* [X22: point 1]
 * Explain following in here.
 * module_exit() macro defines the function to be called during module removal time.
 */
module_exit(ex3_exit);
