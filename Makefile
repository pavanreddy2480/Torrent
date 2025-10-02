CXX      = g++
CXXFLAGS = -Wall -O2 -pthread -std=c++17 -Wno-deprecated-declarations

# --- macOS OpenSSL flags ---
OPENSSL_PREFIX = $(shell brew --prefix openssl@3)
OPENSSL_INC    = -I$(OPENSSL_PREFIX)/include
OPENSSL_LIB    = -L$(OPENSSL_PREFIX)/lib

# directories
CLIENT_DIR  = client
TRACKER_DIR = tracker

# targets
CLIENT   = $(CLIENT_DIR)/client
TRACKER1 = $(TRACKER_DIR)/tracker1
TRACKER2 = $(TRACKER_DIR)/tracker2

# default target
all: $(CLIENT) $(TRACKER1) $(TRACKER2)

# ----- build rules -----
$(CLIENT): $(CLIENT_DIR)/client.cpp
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) -o $@ $< $(OPENSSL_LIB) -lreadline -lcrypto

# Both tracker executables are built from the same source file
$(TRACKER1): $(TRACKER_DIR)/tracker.cpp $(TRACKER_DIR)/tracker_common.hpp
	$(CXX) $(CXXFLAGS) -o $(TRACKER_DIR)/tracker1 $< $(OPENSSL_LIB) -lreadline

$(TRACKER2): $(TRACKER_DIR)/tracker.cpp $(TRACKER_DIR)/tracker_common.hpp
	$(CXX) $(CXXFLAGS) -o $(TRACKER_DIR)/tracker2 $< $(OPENSSL_LIB) -lreadline

# ----- convenience run targets -----
run-client: $(CLIENT)
	@echo "Starting client..."
	./$(CLIENT) tracker_info.txt

run-tracker1: $(TRACKER1)
	@echo "Starting tracker 1..."
	./$(TRACKER1) tracker_info.txt 1

run-tracker2: $(TRACKER2)
	@echo "Starting tracker 2..."
	./$(TRACKER2) tracker_info.txt 2

clean:
	rm -f $(CLIENT) $(TRACKER1) $(TRACKER2)

