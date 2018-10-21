VPATH = layer:tool

OBJECTS = main.o util.o sniffer_ip.o sniffer_tcp.o sniffer_udp.o sniffer_icmp.o
G++ = g++ -o $@ -c $< -pthread -std=c++14

sniffer: $(OBJECTS)
	g++ -o sniffer $(OBJECTS) -lpthread

main.o: main.cpp util.hpp sniffer_eth.hpp sniffer_ip.hpp sniffer_tcp.hpp sniffer_udp.hpp sniffer_icmp.hpp
	$(G++)

util.o: util.cpp util.hpp sniffer_eth.hpp sniffer_ip.hpp sniffer_tcp.hpp sniffer_udp.hpp sniffer_icmp.hpp
	$(G++)

sniffer_ip.o: sniffer_ip.cpp sniffer_ip.hpp sniffer_eth.hpp
	$(G++)

sniffer_tcp.o: sniffer_tcp.cpp sniffer_tcp.hpp sniffer_ip.hpp
	$(G++)

sniffer_udp.o: sniffer_udp.cpp sniffer_udp.hpp sniffer_ip.hpp
	$(G++)

sniffer_icmp.o: sniffer_icmp.cpp sniffer_icmp.hpp sniffer_ip.hpp
	$(G++)

clean:
	rm *.o sniffer
