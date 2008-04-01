#ifndef __COMPAT24_H
#define __COMPAT24_H 1

int genl_init(void);
void genl_exit(void);

int random32_init(void);

void init_kthread(void);

void rcu_init(void);

#endif /* compat24.h */
