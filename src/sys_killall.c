/*
 * Copyright (C) 2025 pdnguyen of HCMC University of Technology VNU-HCM
 */

/* Sierra release
 * Source Code License Grant: The authors hereby grant to Licensee
 * personal permission to use and modify the Licensed Source Code
 * for the sole purpose of studying while attending the course CO2018.
 */

#include "common.h"
#include "syscall.h"
#include "stdio.h"
#include "libmem.h"
#include <pthread.h>
#include <queue.h>
#include <string.h>

pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
int __sys_killall(struct pcb_t *caller, struct sc_regs *regs)
{
    char proc_name[100];
    uint32_t data;

    // hardcode for demo only
    uint32_t memrg = regs->a1;

    /* TODO: Get name of the target proc */
    // proc_name = libread..
    int i = 0;
    data = 0;
    while (data != -1)
    {
        libread(caller, memrg, i, &data);
        proc_name[i] = data;
        if (data == -1)
            proc_name[i] = '\0';
        i++;
    }
    printf("The procname retrieved from memregionid %d is \"%s\"\n", memrg, proc_name);


    /* TODO: Traverse proclist to terminate the proc
     *       stcmp to check the process match proc_name
     */
    // caller->running_list
    // caller->mlq_ready_queu

    /* TODO Maching and terminating
     *       all processes with given
     *        name in var proc_name
     */

    struct pcb_t *p;
    pthread_mutex_lock(&queue_lock);
    const char *filename;
    int a = caller->running_list->size;
    for (int i = 0; i < a; i++)
    {
       
        p = caller->running_list->proc[i];
        filename = strrchr(p->path, '/');
        if (filename)
            filename++; // bỏ dấu '/'
        else
            filename = p->path;
        if (strcmp(filename, proc_name) == 0)
        {
            p->pc = p->code->size;
            free_pcb_memph(p);
            removeFromQueue(caller->running_list, p);
            a--;
            i--;
        }
    }

    // Duyệt running_list
#ifdef MLQ_SCHED
    for (int prio = 0; prio < 140; prio++)
    {
        struct queue_t *q = &caller->mlq_ready_queue[prio];
        a= q->size;
        for (int k = 0; k < a; k++)
        {
            p = q->proc[k];

            filename = strrchr(p->path, '/');
            if (filename)
                filename++;
            else
                filename = p->path;

            if (strcmp(filename, proc_name) == 0)
            {   
                p->pc = -1;
                free_pcb_memph(p);
                removeFromQueue(q, p);
                a--;
                k--;
            }
        }
    }
#else
    a=caller->ready_queue->size;
    for (int j = 0; j < caller->ready_queue->size; j++)
    {
        p = caller->ready_queue->proc[j];

        filename = strrchr(proc->path, '/');
        if (filename)
            filename++;
        else
            filename = p->path;
        if (strcmp(filename, proc_name) == 0)
        {
            p->pc = -1;
            free_pcb_memph(p);
            removeFromQueue(caller->ready_queue, p);
            a--;
            j--;
        }
    }
#endif
    pthread_mutex_unlock(&queue_lock); 
    return 0;
}
