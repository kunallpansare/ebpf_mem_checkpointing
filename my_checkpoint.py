from bcc import BPF

program = r"""
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/bpf.h>

BPF_PERF_OUTPUT(output);

struct data_t {
    u32 pid;
    struct vm_area_struct * address;
    u64 vm_start;
    u64 vm_end;
    u64 vm_curr;
    u64 vm_flags;
    u64 start_stack;
    u64 start_brk;
};

struct command {
    char command[8];
};

struct dump_t {
    char data[4096];
    u64 next_address;
};


BPF_HASH(store_map, u32, struct data_t, 10);
BPF_HASH(restore_map, u32, struct data_t, 10);
BPF_HASH(data_map, u64, struct dump_t, 1024 * 256);
BPF_ARRAY(copy_map, struct dump_t, 10);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char filename[25];
    bpf_probe_read_user(filename, sizeof(filename), args->filename);
    char target_path1[] = "/tmp/ready_to_checkpoint";
    char target_path2[] = "/tmp/ready_to_restore";
    u32 j = 0;
    char flag = 0;

    j = 0;
    flag = 0;
    while(j < 24){
    	if(filename[j] != target_path1[j]){flag = 1; break;};
    	j++;
    }
    if(flag == 0){
        // vma and pid read code
        u32 pid = bpf_get_current_pid_tgid();
        struct mm_struct* mm = NULL;
        struct task_struct *t = (struct task_struct *)bpf_get_current_task();
        bpf_probe_read_kernel(&mm, sizeof(mm), &t->mm);
        if (!mm) return 0;
        struct vm_area_struct *vma;
        u64 vm_start = 0;
        u64 vm_end = 0;
        u64 vm_flags = 0;
        u64 start_stack = 0;
        u64 start_brk = 0;
        bpf_probe_read(&vma, sizeof(struct vm_area_struct *), &mm->mmap);
        bpf_probe_read(&vm_start, sizeof(u64), &vma->vm_start);
        bpf_probe_read(&vm_end, sizeof(u64), &vma->vm_end);
        bpf_probe_read(&vm_flags, sizeof(u64), &vma->vm_flags);
        bpf_probe_read(&start_stack, sizeof(u64), &(mm->start_stack));
        bpf_probe_read(&start_brk, sizeof(u64), &(mm->start_brk));


        bpf_trace_printk("openat called with file: %s \n", filename);
        struct data_t data = {
            .pid = pid, 
            .address = vma, 
            .vm_start = vm_start, 
            .vm_end = vm_end,
            .vm_curr = vm_start,
            .vm_flags = vm_flags,
            .start_stack = start_stack,
            .start_brk = start_brk
        };
        if(store_map.lookup(&pid) != NULL) return 0; 
        store_map.insert(&pid, &data);
    }
    flag = 0;
    j = 0;
        while(j < 21){
    	if(filename[j] != target_path2[j]){flag = 1; break;};
    	j++;
    }
    if(flag == 0){
        bpf_trace_printk("openat called with file: %s \n", filename);

        // vma and pid read code
        u32 pid = bpf_get_current_pid_tgid();
        struct mm_struct* mm = NULL;
        struct task_struct *t = (struct task_struct *)bpf_get_current_task();
        bpf_probe_read_kernel(&mm, sizeof(mm), &t->mm);
        if (!mm) return 0;
        struct vm_area_struct *vma;
        u64 vm_start = 0;
        u64 vm_end = 0;
        u64 vm_flags = 0;
        u64 start_stack = 0;
        u64 start_brk = 0;
        bpf_probe_read(&vma, sizeof(struct vm_area_struct *), &mm->mmap);
        bpf_probe_read(&vm_start, sizeof(u64), &vma->vm_start);
        bpf_probe_read(&vm_end, sizeof(u64), &vma->vm_end);
        bpf_probe_read(&vm_flags, sizeof(u64), &vma->vm_flags);
        bpf_probe_read(&start_stack, sizeof(u64), &(mm->start_stack));
        bpf_probe_read(&start_brk, sizeof(u64), &(mm->start_brk));


        struct data_t data = {
            .pid = pid, 
            .address = vma, 
            .vm_start = vm_start, 
            .vm_end = vm_end,
            .vm_curr = vm_start,
            .vm_flags = vm_flags,
            .start_stack = start_stack,
            .start_brk = start_brk
        };
        restore_map.insert(&pid, &data);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_access) {
    char filename[25];
    bpf_probe_read_user(filename, sizeof(filename), args->filename);
    char target_path1[] = "/tmp/checkpoint_complete";
    char target_path2[] = "/tmp/restore_complete";

    
    u32 j = 0;
    char flag = 0;
    while(j < 24){
    	if(filename[j] != target_path1[j]){flag = 1; break;};
    	j++;
    }
    if(flag == 0){
        // bpf_trace_printk("access called with file: %s \n", filename);
        u32 pid = bpf_get_current_pid_tgid();
        // struct mm_struct* mm = NULL;
        struct task_struct *t = (struct task_struct *)bpf_get_current_task();
        // bpf_probe_read_kernel(&mm, sizeof(mm), &t->mm);
        
        u64 read_address = 0;
        struct data_t *d = store_map.lookup(&pid);
        if(d == NULL) return  0;

        // Skip vma_region if not MAP_ANONYMOUS or memory belongs to Stack region
        if(d->vm_flags != 0){   //not needed as atleast one flag will not be zero and atlease one of them would be set to something
            if ((d->vm_flags & MAP_ANONYMOUS) == 0 || (u64)d->vm_end >= d->start_stack || (u64)d->vm_start < d->start_brk) {
                bpf_probe_read(&(d->address), sizeof(struct vm_area_struct *), &(d->address->vm_next));
                if(d->address == NULL){
                    struct command c = {.command = "store"};
                    output.perf_submit(args, &c, sizeof(c));
                    return 0;
                }
                bpf_probe_read(&(d->vm_start), sizeof(u64), &d->address->vm_start);
                bpf_probe_read(&(d->vm_end), sizeof(u64), &d->address->vm_end);
                bpf_probe_read(&(d->vm_flags), sizeof(u64), &d->address->vm_flags);
                return 0;
            } else {
                // bpf_trace_printk("Anon : flag : %lx  AF : %lx vm_region : %lx\n", d->vm_flags, MAP_ANONYMOUS, d->address);
            }
        }


        
        bpf_probe_read(&read_address, sizeof(u64), &(d->address)); // (reusing read_address)
        if(read_address == 0) return 0;
        u32 zero = 0;
        struct dump_t *dt = copy_map.lookup(&zero);
        if(dt == NULL) return 0;
        for(u32 i = 0; i < 4096; i += sizeof(dt->data)){
            read_address = d->vm_curr;
            bpf_probe_read_user(dt->data, sizeof(dt->data), (const void *)(d->vm_curr));
            // bpf_trace_printk("Address %lx data : %s \n", d->vm_curr, dt->data);
            (*d).vm_curr += sizeof(dt->data);
            if(d->vm_curr >= d->vm_end){
                bpf_probe_read(&(d->address), sizeof(struct vm_area_struct *), &(d->address->vm_next));
                // bpf_trace_printk("VMA Region Changed with %lx\n", d->address);
                if(d->address == NULL){
                    dt->next_address = 0;
                    data_map.insert(&read_address, dt);
                    struct command c = {.command = "store"};
                    output.perf_submit(args, &c, sizeof(c));
                    return 0;
                }
                bpf_probe_read(&(d->vm_start), sizeof(u64), &d->address->vm_start);
                bpf_probe_read(&(d->vm_end), sizeof(u64), &d->address->vm_end);
                bpf_probe_read(&(d->vm_flags), sizeof(u64), &d->address->vm_flags);
                (*d).vm_curr = d->vm_start;
            }
            dt->next_address = (*d).vm_curr;
            data_map.insert(&read_address, dt);
        }
    }

    j = 0;
    flag = 0;
    while(j < 21){
    	if(filename[j] != target_path2[j]){flag = 1; break;};
    	j++;
    }
    if(flag == 0){
        // bpf_trace_printk("access called with file: %s \n", filename);
        u32 pid = bpf_get_current_pid_tgid();        
        struct data_t *d = restore_map.lookup(&pid);
        if(d == NULL) return  0;
        struct data_t dd = *d;
        // bpf_trace_printk("VMA region : %lx\n", dd.address);
        if(dd.address == NULL){
            // everything is completed so remove every thing related to this process
            store_map.delete(&pid);
            restore_map.delete(&pid);
            return 0;
        }

        struct dump_t *dt = 0;
        dt = data_map.lookup(&dd.vm_curr);
        if(dt == NULL)
        {
            // everything is completed so remove every thing related to this process
            store_map.delete(&pid);
            restore_map.delete(&pid);
            struct command c = {.command = "restore"};
            output.perf_submit(args, &c, sizeof(c));
            return 0;
        }
        u32 zero = 0;
        struct dump_t *dt_temp = copy_map.lookup(&zero);
        if(dt_temp == NULL) return 0;

        bpf_probe_read(&(dt_temp->data), sizeof(dt_temp->data), &(dt->data));
        // struct dump_t data = *dt;

        // bpf_trace_printk("next address : %lx\n", data.next_address);
        u32 res = bpf_probe_write_user((void *)(d->vm_curr), (void *)(dt_temp->data), sizeof(dt_temp->data));
        data_map.delete(&dd.vm_curr);
        // bpf_trace_printk("Return code after writing : %d", res);
        (*d).vm_curr = dt->next_address;
    }
    return 0;
}
"""

b = BPF(text=program)
# b.trace_print()


def print_event(cpu, data, size):
    print(data)
    data = b["output"].event(data)
    if(data.command.decode() == "store"):
        # create file /tmp/checkpoint_complete
        with open("/tmp/checkpoint_complete", 'w') as file:
            file.write("Store complete\n")
            
    elif(data.command.decode() == "restore"):
        with open("/tmp/restore_complete", 'w') as file:
            file.write("Store complete\n")

# opens perf ring and takes callback function to be user whenever there is a data to read from the buffer
# b["output"].open_perf_buffer()
b["output"].open_perf_buffer(print_event)
while True:
    # If any data present in  perf buffer then print_event will be called
    b.perf_buffer_poll(5)
