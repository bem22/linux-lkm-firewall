#define PROC_FD "firewallExtension"
#define DEBUG 0
#define EXEC_SIZE 4097
#define PATH_SIZE 256

// --- Semaphores ---
DECLARE_RWSEM(sem_rules);
DEFINE_SEMAPHORE(sem_proc);
static int lock_flag = 0;

// --- Data structures and functions ---
typedef struct Node
{
    unsigned int port_no;
    char *exec;
    struct Node *next;
} Node;

typedef struct list
{
    struct Node *node;
} list;

static void list_init(list *list);
static int list_insert(list *list, int port, char* exec);
static void list_print(list *list);
static int list_find(list *list, int port, char* exec);
static void list_destroy(list *list);

// --- Global variables ---

struct nf_hook_ops *reg;

static struct proc_dir_entry *proc_file;struct nf_hook_ops *reg;

static struct proc_dir_entry *proc_file;

static struct list rules;