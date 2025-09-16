CXX=g++
CXXFLAGS=-Wall -O2

# directories
CLIENT_DIR=client
TRACKER_DIR=tracker

# targets
CLIENT=$(CLIENT_DIR)/client
TRACKER1=$(TRACKER_DIR)/tracker1
TRACKER2=$(TRACKER_DIR)/tracker2

all: $(CLIENT) $(TRACKER1) $(TRACKER2)

$(CLIENT): $(CLIENT_DIR)/client.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

$(TRACKER1): $(TRACKER_DIR)/tracker1.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

$(TRACKER2): $(TRACKER_DIR)/tracker2.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

run-client: $(CLIENT)
	./$(CLIENT)

run-tracker1: $(TRACKER1)
	./$(TRACKER1)

run-tracker2: $(TRACKER2)
	./$(TRACKER2)

clean:
	rm -f $(CLIENT) $(TRACKER1) $(TRACKER2)