#ifndef __NET_SOCK_WRAPPER_H
#define __NET_SOCK_WRAPPER_H 1

#include_next <net/sock.h>

#ifndef __sk_user_data
#define __sk_user_data(sk) ((*((void __rcu **)&(sk)->sk_user_data)))

#define rcu_dereference_sk_user_data(sk)       rcu_dereference(__sk_user_data((sk)))
#define rcu_assign_sk_user_data(sk, ptr)       rcu_assign_pointer(__sk_user_data((sk)), ptr)
#endif

#endif
