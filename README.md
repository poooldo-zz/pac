Pac
================

What?
-----------------------

Pac capture packets using libpcap and store the last n packets in RAM buffer. 

On event (signal USR1), it dumps the buffer in a pcap file.
On signal USR2, it outputs on stdout the # of packets per second it captures (regarding the bpf filter enabled).

How?
-----------------------
Create a configuration file with the following parameters (all optional):

    device=""; # the device to start the capture, default: any
    filter=""; # the filter to apply to the capture, default: ""
    output=""; # the output file, default: /tmp/default.pcap
    buffer=""; # the in-memory circular buffer size (in packets), default: 1000


    ./pac -f default.cfg
    Process PID: 8816
    circular buffer cap: 10000
    (kill -USR2 8816 on a diffrent terminal)
    # of packets since 1517847207: 494
    pckts / sec: 41
