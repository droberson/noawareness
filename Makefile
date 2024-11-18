CC = gcc
CFLAGS = -g -Wall -Iinclude
LFLAGS =
LIBS = -ljson-c

SRC_DIR = src
BUILD_DIR = build
MD5_DIR = src/md5

SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
OFILES = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC_FILES))
MD5_OBJ = $(MD5_DIR)/md5c.o

TEST_DIR = test
TEST_SRC_FILES = $(wildcard $(TEST_DIR)/*.c)
TEST_OFILES = $(patsubst $(TEST_DIR)/%.c, $(BUILD_DIR)/%.o, $(TEST_SRC_FILES))
TEST_BINARIES = $(patsubst $(TEST_DIR)/%.c, $(BUILD_DIR)/%, $(TEST_SRC_FILES))

all: noawareness test

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c include/*.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(MD5_OBJ): $(MD5_DIR)/md5c.c $(MD5_DIR)/md5.h
	$(CC) $(CFLAGS) -c -o $@ $<

noawareness: $(OFILES) $(MD5_OBJ)
	$(CC) $(CFLAGS) $(LFLAGS) $(OFILES) $(MD5_OBJ) -o $@ $(LIBS)

$(BUILD_DIR)/test-endswith: $(TEST_DIR)/test-endswith.c $(BUILD_DIR)/string.o
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/test-sha256: $(TEST_DIR)/test-sha256.c $(BUILD_DIR)/sha256.o
	$(CC) $(CFLAGS) $^ -o $@

test: $(TEST_BINARIES)
	@echo "Running tests..."
	@for test in $(TEST_BINARIES); do \
		echo "Running $$test..."; \
		$$test; \
	done

clean:
	rm -rf $(BUILD_DIR)/* $(MD5_OBJ) noawareness *~
