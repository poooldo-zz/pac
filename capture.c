#include "capture.h"

void 
write_pcap_header(void) 
{
    struct pcap_file_header file_header;
    
    file_header.magic = 0xa1b2c3d4;
    file_header.version_major = 2;
    file_header.version_minor = 4;
    file_header.thiszone = 0;
    file_header.sigfigs = 0;
    file_header.snaplen = 65535;
    file_header.linktype = DLT_EN10MB;      

    fwrite((char*)&file_header, sizeof(file_header), 1, fd);
}

void write_pcap_packet(
    const u_char *packet,
    struct pcap_pkthdr * packet_header
)
{
    struct pcap_sf_pkthdr sf_hdr;

    sf_hdr.ts.tv_sec  = packet_header->ts.tv_sec;
    sf_hdr.ts.tv_usec = packet_header->ts.tv_usec;
    sf_hdr.caplen     = packet_header->caplen;
    sf_hdr.len        = packet_header->len;
    
    (void)fwrite(&sf_hdr, sizeof(sf_hdr), 1, fd);
    (void)fwrite((char *)packet, packet_header->caplen, 1, fd);
}

void 
write_packet_info(
    const u_char *packet, 
    struct pcap_pkthdr packet_header
) 
{
    write_buffer(circular_buffer, &packet_header, packet);
}

void 
packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{
    nb_packets += 1;
    write_packet_info(packet_body, *packet_header);
    return;   
}

void 
packet_count_reset() 
{
    nb_packets = 0;
}

int64_t 
get_packet_count() 
{
    return nb_packets;
}

int
start_capture(
    const char *_device, 
    const char *_filter_exp,
    const char *_output,
    const char *_buf_size
) 
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    bpf_u_int32 subnet_mask, ip;
    struct _cb_el * current = NULL;
    int i = 0;

    if(pcap_lookupnet(_device, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get information for device: %s\n", _device);
        ip = 0;
        subnet_mask = 0;
    }

    handle = pcap_open_live(_device, BUFSIZ, 1, 1000, error_buffer);
    if(handle == NULL) {
        printf("Could not open %s - %s\n", _device, error_buffer);
        return -1;
    }

    if(strlen(_filter_exp) > 0) {
        if(pcap_compile(handle, &filter, _filter_exp, 0, ip) == -1) {
            printf("Bad filter - %s\n", pcap_geterr(handle));
            return -1;
        }
    
        if(pcap_setfilter(handle, &filter) == -1) {
            printf("Error setting filter - %s\n", pcap_geterr(handle));
            return -1;
        }
    }

    fd = fopen(_output, "w");
    if(fd != NULL) {
        write_pcap_header();
    } else {
        printf("Error while opening file %s\n", _output);
        return -1;
    }

    if((circular_buffer = create_buffer(atoi(_buf_size))) == NULL) {
        printf("unable to create circular buffer\n");
        return -1;
    }

    printf("circular buffer cap: %d\n", circular_buffer->cap);

    pcap_loop(handle, 0, packet_handler, NULL);

    current = read_buffer(circular_buffer);
    for(i = 0; i < circular_buffer->size; ++i) {
        write_pcap_packet(current->data, current->header);
        current = current->next;
    }
   
    delete_buffer(circular_buffer); 

    return 0;
}

void 
stop_capture(void)
{
    if(handle != NULL) {
        pcap_breakloop(handle);
    }
}
