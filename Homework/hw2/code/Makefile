CXX = gcc

SOURCE = hw2.c
TARGET = hw2.o

LIB_SOURCE = logger.c
LIB = logger.so
EXEC = logger


all:
	$(CXX) -D_GNU_SOURCE -o $(LIB) --shared -fPIC $(LIB_SOURCE) -ldl
	$(CXX) -o $(TARGET) -c -g -Wall $(SOURCE)
	$(CXX) -o $(EXEC) $(TARGET)

.PHONY: all clean
