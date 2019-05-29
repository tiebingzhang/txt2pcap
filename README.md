## txt2pcap

A PHP implementation of converting plain text hex packet files to PCAP files that can be read by tcpdump/wireshark. wireshark comes with a C-implementation named "text2pcap".

The script is standalone and doesn't have any external dependencies.

## usage
```
./txt2cap input-file output-filename
```

## input file

Input file has the following format
```
timestamp bytes-offset: byte data
timestamp: HH:MM:SS.uuuuuu
offset is in hex format and needs to start with at least three 000, such as "000000" or "000C40"
byte data is in hex format, seperated by space
```

The input data is assumed to have IP headers, but not Ethernet header. A dummy Ethernet header is added to every packet. Modify the code to your need if this is your case.

## why
1. It's fun!
2. This gives more control in error detection than the text2pcap binary in wireshark.
