CXX      = g++
CXXFLAGS = -Wall -O2 -pthread -std=c++17

# --- macOS OpenSSL flags ---
# Use 'shell' to ask Homebrew where OpenSSL is installed
OPENSSL_PREFIX = $(shell brew --prefix openssl)
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
# Added the OpenSSL flags and -lcrypto for the client
$(CLIENT): $(CLIENT_DIR)/client.cpp
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) -o $@ $< $(OPENSSL_LIB) -lreadline -lcrypto

$(TRACKER1): $(TRACKER_DIR)/tracker1.cpp $(TRACKER_DIR)/tracker_common.hpp
	$(CXX) $(CXXFLAGS) -o $@ $<

$(TRACKER2): $(TRACKER_DIR)/tracker2.cpp $(TRACKER_DIR)/tracker_common.hpp
	$(CXX) $(CXXFLAGS) -o $@ $<

# ----- convenience run targets -----
run-client: $(CLIENT)
	@echo "Starting client (connect manually to a tracker)..."
	./$(CLIENT) 127.0.0.1 6000

run-tracker1: $(TRACKER1)
	@echo "Starting tracker1 on 127.0.0.1:6000 (peer:127.0.0.1:7000)..."
	./$(TRACKER1) 127.0.0.1 6000 127.0.0.1 7000

run-tracker2: $(TRACKER2)
	@echo "Starting tracker2 on 127.0.0.1:7000 (peer:127.0.0.1:6000)..."
	./$(TRACKER2) 127.0.0.1 7000 127.0.0.1 6000

# Start both trackers in background, then run client
run-all: all
	@echo "Launching trackers and client..."
	@./$(TRACKER1) 127.0.0.1 6000 127.0.0.1 7000 & \
	 ./$(TRACKER2) 127.0.0.1 7000 127.0.0.1 6000 & \
	 sleep 1 && ./$(CLIENT) 127.0.0.1 6000

clean:
	rm -f $(CLIENT) $(TRACKER1) $(TRACKER2)

