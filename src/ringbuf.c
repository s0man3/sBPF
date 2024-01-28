#include <linux/sbpf.h>
#include <linux/wait.h>
#include <linux/irq_work.h>
#include <linux/mm_types.h>

struct sbpf_ringbuf {
        wait_queue_head_t waitq;
        struct irq_work work;
        struct page **pages;
}

struct sbpf_ringbuf_map {
	struct sbpf_map;
	struct sbpf_ringbuf *rb;
}
