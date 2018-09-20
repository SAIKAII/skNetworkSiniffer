sniffer: main.o util.o
	g++ -o sniffer main.o util.o

main.o: main.cpp network_packet.hpp util.hpp
	g++ -o main.o -c main.cpp -std=c++14

util.o: util.cpp network_packet.hpp util.hpp
	g++ -o util.o -c util.cpp -std=c++14


clean:
	rm *.o
