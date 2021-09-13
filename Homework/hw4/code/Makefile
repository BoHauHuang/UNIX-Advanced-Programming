CXX = g++
CXX_FLAG = -O3 -Wall -lcapstone

SOURCE = sdb
TARGET = hw4

hw4:
	$(CXX) -c $(SOURCE).cpp -o $(TARGET).o
	$(CXX) $(TARGET).o $(CXX_FLAG) -o $(TARGET)

clean:
	rm *.o
