VPATH = layer:tool

OBJECTS = main.o util.o sniffer_ip.o sniffer_tcp.o sniffer_udp.o
G++ = g++ -g -o $@ -c $< -std=c++14

sniffer: $(OBJECTS)
	g++ -o sniffer $(OBJECTS)

main.o: main.cpp util.hpp sniffer_eth.hpp sniffer_ip.hpp sniffer_tcp.hpp sniffer_udp.hpp
	$(G++)

util.o: util.cpp util.hpp
	$(G++)

sniffer_ip.o: sniffer_ip.cpp sniffer_ip.hpp
	$(G++)

sniffer_tcp.o: sniffer_tcp.cpp sniffer_tcp.hpp
	$(G++)

sniffer_udp.o: sniffer_udp.cpp sniffer_udp.hpp
	$(G++)

clean:
	rm *.o sniffer
