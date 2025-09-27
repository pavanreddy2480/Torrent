## Project: Distributed Tracker and Client System

### Components

1. **Client (`client.cpp`)**
   
   - Connects to a tracker server using TCP.
   - Reads commands interactively using `readline`.
   - Sends commands to the tracker in a structured frame format (`[frame_len][session_id][payload]`).
   - Receives responses from the tracker and updates session information.
   - Supports commands: `create_user`, `login`, `logout`, `create_group`, `join_group`, `accept_request`, `list_groups`.
2. **Tracker 1 (`tracker1.cpp`)**
   
   - Listens on a specified IP and port.
   - Forwards non-sync commands to a peer tracker using `SyncQueue`.
   - Spawns a new thread for each incoming client connection (`sessionWorker`).
3. **Tracker 2 (`tracker2.cpp`)**
   
   - Listens on a specified IP and port.
   - Handles requests locally; does not forward commands.
   - Accepts connections concurrently using detached threads.
4. **Common Utilities (`tracker_common.hpp` / `tracker_common.cpp`)**
   
   - Implements network utilities (`readn`, `writen`, `hton64`, `ntoh64`).
   - Provides `Tracker` class for managing users, sessions, and groups.
   - Implements `SyncQueue` for asynchronous command forwarding between trackers.
   - Implements session handling logic (`sessionWorker`) and listener setup (`prepare_listener`).

---

### Implementation Details

#### Session Management

- Each client session is assigned a unique 64-bit session ID (`nextId()` in `Tracker`).
- Session IDs are tracked in an unordered map (`sessions`) and included in all communication frames.
- Clients store the session ID and include it in subsequent requests for identification.

#### Command Processing

- Commands are parsed using string streams.
- Tracker validates commands and user authentication before performing operations.
- Responses include updated session IDs and command results.

#### Synchronization Approach

- `SyncQueue` is used to forward commands from Tracker 1 to Tracker 2 asynchronously.
- `enqueue()` pushes commands to a thread-safe queue, and `run()` transmits them to the peer tracker.
- `mutex` and `condition_variable` ensure safe concurrent access to shared data structures.

#### Concurrency Handling

- Each tracker uses a multi-threaded approach:
  - `sessionWorker` threads handle each client connection independently.
  - Detached threads allow simultaneous client interactions without blocking the main listener.
- `Tracker` class protects critical metadata with `mutex` locks to avoid race conditions.

#### Metadata Organization

- `users`: `unordered_map<string, string>` mapping usernames to passwords.
- `sessions`: `unordered_map<u64, string>` mapping session IDs to logged-in usernames.
- `groups`: `unordered_map<string, GroupInfo>` storing group owner, members, and pending requests.
- `SyncQueue`: `deque<SyncItem>` storing commands to be forwarded asynchronously.

---

### Network Protocol

- All messages follow a **framed protocol**:
-[4-byte frame length][8-byte session ID][payload]
- Frame length includes the session ID and payload length.  
- Session IDs are transmitted in network byte order (`hton64` / `ntoh64`).  
- Payload for sync commands is prefixed with `"SYNC:"` to distinguish forwarded messages.

---

### Justification of Design Choices
1. **Thread-per-connection**: Simplifies handling of concurrent clients while keeping the code readable.  
2. **Detached threads**: Avoids blocking the main listener, enabling continuous acceptance of new connections.  
3. **Mutex-protected metadata**: Ensures safe concurrent access to users, sessions, and group data.  
4. **SyncQueue**: Efficiently handles cross-tracker synchronization without blocking the main tracker loop.  
5. **Framed TCP protocol**: Guarantees correct message boundaries and enables handling of arbitrary-length payloads.  

---

### How to Run
1. **Compile**:  
 ```bash
 g++ client.cpp -o client -lreadline -pthread
 g++ tracker1.cpp tracker_common.cpp -o tracker1 -pthread
 g++ tracker2.cpp tracker_common.cpp -o tracker2 -pthread


./tracker1 <bind_ip> <bind_port> <peer_ip> <peer_port>
./tracker2 <peer_ip> <peer_port> <bind_ip> <bind_port>
./client <tracker_ip> <tracker_port>
