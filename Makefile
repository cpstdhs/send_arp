all : pcap_test

pcap_test: main.o
	g++ -g -o send_arp send_arp.o -lpcap

main.o:
	g++ -g -c -o send_arp.o send_arp.cpp

clean:
	rm -f send_arp
	rm -f *.o

