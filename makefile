sniffer: main.o util.o
	g++ -o sniffer main.o util.o -std=c++14

main.o: main.cpp
	g++ -o main.o -c main.cpp -std=c++14

util.o: util.cpp
	g++ -o util.o -c util.cpp -std=c++14


clean:
	rm *.o
