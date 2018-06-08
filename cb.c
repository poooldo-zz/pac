#include "cb.h"

struct cb *
create_buffer(
    unsigned int _size
)
{
    struct cb * buffer = NULL;
    struct _cb_el * el = NULL;
    int i = 0;

    buffer = (struct cb *) malloc(sizeof(struct cb));
    if(buffer == NULL) {
        return buffer;
    }

    el = (struct _cb_el *) malloc(sizeof(struct _cb_el));
    if(el == NULL) {
        free(buffer);
        return NULL;
    }
    el->header      = NULL;
    el->data        = NULL;
    el->next        = NULL;
    buffer->start   = el;
    buffer->end     = el;
    buffer->write_p = el;
    buffer->read_p  = el;
    buffer->cap     = 1; 
    
    for(i = 0; i < _size-1; ++i) {
        el = (struct _cb_el *) malloc(sizeof(struct _cb_el));
        if(el == NULL) {
            continue;
        } else {
            buffer->end->next = el;
            el->next = buffer->start;
            buffer->end = el;
            el->header = NULL;
            el->data = NULL;
            buffer->cap = buffer->cap + 1;
        }
    }
    return buffer;
}

void
delete_buffer(
    struct cb * _buffer
)
{
    struct _cb_el * start = _buffer->start;
    struct _cb_el * next  = _buffer->start;
    struct _cb_el * curr  = NULL;
    int i = 0;    

    /* buffer is full */
    if(_buffer->size == _buffer->cap) {
        do {
            curr = next;
            next = next->next;
            free(curr->header);
            free(curr->data);
            free(curr);
        } while(next != start);
    } else { /* buffer not full */
        for(i = 0; i < _buffer->size; ++i) {
            curr = next;
            next = next->next;
            free(curr->header);
            free(curr->data);
            free(curr);
        }    
    }

    free(_buffer);    
}

struct _cb_el *
read_buffer(
    struct cb * _buffer
)
{
    return _buffer->read_p;
}

void
write_buffer(
    struct cb * _buffer,
    struct pcap_pkthdr * _header,
    const u_char * _data   
)
{
    size_t data_length = 0;

    if(unlikely(_buffer->write_p->header == NULL)) {
        _buffer->write_p->header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    } else {
        data_length = _buffer->write_p->header->caplen;
    }
    _buffer->write_p->header->ts.tv_sec     = _header->ts.tv_sec; 
    _buffer->write_p->header->ts.tv_usec    = _header->ts.tv_usec; 
    _buffer->write_p->header->caplen        = _header->caplen; 
    _buffer->write_p->header->len           = _header->len;
 
    if(unlikely(_buffer->write_p->data == NULL)) {
        _buffer->write_p->data = (u_char *)malloc(_buffer->write_p->header->caplen * sizeof(u_char));
    } else if(data_length <= _buffer->write_p->header->caplen) {
        _buffer->write_p->data = (u_char *)realloc(_buffer->write_p->data, _header->caplen);    
    }

    memcpy(_buffer->write_p->data, _data, _header->caplen);

    /* in a full circular buffer, write_p points to the newest
     * data written whereas read_p is write + 1 i.e. the oldest
     * data written.
     */
    
    /* update write pointer to the next element */
    _buffer->write_p = _buffer->write_p->next;
    if (_buffer->size < _buffer->cap) {
        _buffer->size = _buffer->size + 1;    
    } else {
        /* update read pointer to be write_p + 1 */
        _buffer->read_p = _buffer->write_p;
    }
}
