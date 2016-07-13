# Makefile for SEAL examples
BIN_DIR=../bin
INCLUDE_DIR=../SEAL
CXXFLAGS=-Wall -Wno-unused-function -std=c++11 -O3 -I$(INCLUDE_DIR)
SRCS=enc_zeros.cpp
OBJS=$(SRCS:.cpp=.o)
SEALRUN=$(BIN_DIR)/enc_labels.exe

.PHONY: all clean

all: $(SEALRUN)

$(SEALRUN): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -L$(BIN_DIR) -lseal -o $(SEALRUN)

clean:
	-rm -f $(OBJS) $(SEALRUN)
