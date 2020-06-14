#ifndef __LQ_QUEUE_H_
#define __LQ_QUEUE_H_

#define LQQ_INIT
#define LQQ_INSERT_HEAD(head, elm) do {(elm)->next = (head); (head) = (elm);} while (0)
#define LQQ_FIRST(head) (head)
#define LQQ_REMOVE_HEAD(head) do {(head) = (head)->next; } while (0)
#define LQQ_INSERT
#define LQQ_APPEND
#define LQQ_FOREACH
#define LQQ_CONSUME_HEAD

#endif // __LQ_QUEUE_H_
