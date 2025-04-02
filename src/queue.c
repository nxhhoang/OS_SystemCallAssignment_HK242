#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

int empty(struct queue_t *q)
{
	if (q == NULL)
		return 1;
	return (q->size == 0);
}

void enqueue(struct queue_t *q, struct pcb_t *proc)
{
	/* TODO: put a new process to queue [q] */
	if (q != NULL && q->size < MAX_QUEUE_SIZE)
	{
		q->proc[q->size] = proc;
		++q->size;
	}
}

struct pcb_t *dequeue(struct queue_t *q)
{
	/* TODO: return a pcb whose prioprity is the highest
	 * in the queue [q] and remember to remove it from q
	 * */
	if (empty(q))
		return NULL;

	struct pcb_t *proc = NULL;
#ifdef MLQ_SCHED
	proc = q->proc[0];
	for (int i = 0; i + 1 < q->size; ++i)
		q->proc[i] = q->proc[i + 1];

	q->proc[q->size - 1] = NULL;
	--q->size;

#else
	int currentPrio = MAX_PRIO;
	int pos = -1;
	for (int i = 0; i < q->size; ++i)
	{
		if (currentPrio > q->proc[i]->priority)
		{
			currentPrio = q->proc[i]->priority;
			pos = i;
		}
	}

	if (pos != -1)
	{
		proc = q->proc[pos];
		for (int i = pos; i < q->size - 1; ++i)
		{
			q->proc[i] = q->proc[i + 1];
		}
	}
#endif

	return proc;
}
