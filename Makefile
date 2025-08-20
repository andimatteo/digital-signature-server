CC = g++
CFLAGS = -Wall -Wextra -MMD -MP -g
CPPFLAGS = -I./src/common -I./src/client -I./src/server
LDFLAGS =
LDLIBS = -lcrypto

OUT_DIR = out
BUILD_DIR = build

COMMON_SRC = $(wildcard src/common/*.cpp)
CLIENT_SRC = $(wildcard src/client/*.cpp)
SERVER_SRC = $(wildcard src/server/*.cpp)

# Build common twice, once per target flavor
COMMON_CLIENT_OBJ = $(patsubst src/common/%.cpp, $(BUILD_DIR)/client_common_%.o, $(COMMON_SRC))
COMMON_SERVER_OBJ = $(patsubst src/common/%.cpp, $(BUILD_DIR)/server_common_%.o, $(COMMON_SRC))
CLIENT_OBJ = $(patsubst src/client/%.cpp, $(BUILD_DIR)/client_%.o, $(CLIENT_SRC))
SERVER_OBJ = $(patsubst src/server/%.cpp, $(BUILD_DIR)/server_%.o, $(SERVER_SRC))

SERVER_BIN = $(OUT_DIR)/server
CLIENT_BIN = $(OUT_DIR)/client

.PHONY: all clean
all: $(SERVER_BIN) $(CLIENT_BIN)
	@echo "Build complete"

$(OUT_DIR) $(BUILD_DIR):
	mkdir -p $@

# -------- compile rules --------
# common for client (no _SERVER)
$(BUILD_DIR)/client_common_%.o: src/common/%.cpp | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# common for server (_SERVER defined)
$(BUILD_DIR)/server_common_%.o: src/common/%.cpp | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -D_SERVER $(CFLAGS) -c $< -o $@

# client-only sources
$(BUILD_DIR)/client_%.o: src/client/%.cpp | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# server-only sources (_SERVER defined)
$(BUILD_DIR)/server_%.o: src/server/%.cpp | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -D_SERVER $(CFLAGS) -c $< -o $@

# -------- link rules --------
$(SERVER_BIN): $(COMMON_SERVER_OBJ) $(SERVER_OBJ) | $(OUT_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(CLIENT_BIN): $(COMMON_CLIENT_OBJ) $(CLIENT_OBJ) | $(OUT_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

# dependencies
-include $(COMMON_CLIENT_OBJ:.o=.d) $(COMMON_SERVER_OBJ:.o=.d) \
         $(CLIENT_OBJ:.o=.d) $(SERVER_OBJ:.o=.d)

clean:
	rm -rf $(OUT_DIR) $(BUILD_DIR)

