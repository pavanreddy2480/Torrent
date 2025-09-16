CXX      = g++
CXXFLAGS = -Wall -O2 -pthread -std=c++17

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
	$(CXX) $(CXXFLAGS) -o $@ $< -lreadline    # link with readline

# Tracker1 and Tracker2 both include tracker_common.hpp automatically
$(TRACKER1): $(TRACKER_DIR)/tracker1.cpp $(TRACKER_DIR)/tracker_common.hpp
	$(CXX) $(CXXFLAGS) -o $@ $<

$(TRACKER2): $(TRACKER_DIR)/tracker2.cpp $(TRACKER_DIR)/tracker_common.hpp
	$(CXX) $(CXXFLAGS) -o $@ $<

# ----- convenience run targets -----
# ----- convenience run targets -----
run-client: $(CLIENT)
	./$(CLIENT)

run-tracker1: $(TRACKER1)
	./$(TRACKER1) 127.0.0.1 6000 127.0.0.1 7000

run-tracker2: $(TRACKER2)
	./$(TRACKER2) 127.0.0.1 7000 127.0.0.1 6000

clean:
	rm -f $(CLIENT) $(TRACKER1) $(TRACKER2)