#include <libconfig.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "capture.h"

time_t start_time, stop_time;

static void 
usr1_handler(
    int signo
)
{
    stop_capture();
}

static void 
usr2_handler(
    int signo
)
{
    time_t stop_time = time(NULL);
    printf("# of packets since %d: %d\n", start_time, get_packet_count());
    do {
        if(stop_time - start_time > 0) {
            printf("pckts / sec: %d\n", get_packet_count() / (stop_time - start_time));
            packet_count_reset();
            break;
        }
        sleep(1);
        stop_time = time(NULL);
    } while(1);

    packet_count_reset();
    start_time = stop_time; 
}

int 
parse_config(
    config_t * _cfg,
    char * filename    
) 
{
    config_init(_cfg);
    if(! config_read_file(_cfg, filename)) {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(_cfg),
            config_error_line(_cfg), config_error_text(_cfg));
        config_destroy(_cfg);
        return EXIT_FAILURE;
    }
    
    return 0;
}

int main(int argc, char **argv) {
    
    const char * device;
    const char * filter;
    const char * output;
    const char * buf_size;
    char * filename = NULL;
    char device_any[] = "any";
    char default_filter[] = "";
    char default_output[] = "/tmp/default.pcap";
    char default_buf_size[] = "1000";
    config_t cfg;
    int c;

    while ((c = getopt(argc, argv, "f:")) != -1) {
        switch (c) {
            case 'f':
                filename = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s -f configfile\n", argv[0]);
                return EXIT_FAILURE;
        }
    }
    
    if(filename == NULL) {
        fprintf(stderr, "Usage: %s -f configfile\n", argv[0]);
        return EXIT_FAILURE;
    }

    parse_config(&cfg, filename);   
    if(!config_lookup_string(&cfg, "device", &device)) {
        fprintf(stderr, "device option not defined in config, switching to \"any\" device\n");
        device = device_any;
    }
    if(!config_lookup_string(&cfg, "filter", &filter)) {
        fprintf(stderr, "no filter option defined, capturing all packets\n");
        filter = default_filter;
    }
    if(!config_lookup_string(&cfg, "output", &output)) {
        fprintf(stderr, "no output option defined, writing to %s\n", default_output);
        output = default_output;
    }
    if(!config_lookup_string(&cfg, "buffer", &buf_size)) {
        fprintf(stderr, "no buffer size option defined, set to %s\n", default_buf_size);
        buf_size = default_buf_size;
    }
    
    if (signal(SIGUSR1, usr1_handler) == SIG_ERR) {
        fputs("An error occurred while setting a signal handler.\n", stderr);
        return EXIT_FAILURE;
    }
   
    start_time = time(NULL);
    packet_count_reset();
    if (signal(SIGUSR2, usr2_handler) == SIG_ERR) {
        fputs("An error occurred while setting a signal handler.\n", stderr);
        return EXIT_FAILURE;
    }
   
    fprintf(stderr, "Process PID: %d\n", getpid()); 
    start_capture(device, filter, output, buf_size);

    return 0;
}
