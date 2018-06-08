#ifndef __CB_H__
#define __CB_H__

#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>


#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

typedef unsigned char   u_char;

struct _cb_el {
    struct pcap_pkthdr * header;
    u_char * data;

    struct _cb_el * next;
};

struct cb {
    struct _cb_el * write_p;
    struct _cb_el * read_p;

    struct _cb_el * start;
    struct _cb_el * end;

    unsigned int size; 
    unsigned int cap; 
};

struct cb * create_buffer(unsigned int);
void delete_buffer(struct cb *);

struct _cb_el * read_buffer(struct cb *);
void write_buffer(struct cb *, struct pcap_pkthdr *, const u_char *);

#endif /* __CB_H__ */
