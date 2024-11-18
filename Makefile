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

all: noawareness

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c include/*.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(MD5_OBJ): $(MD5_DIR)/md5c.c $(MD5_DIR)/md5.h
	$(CC) $(CFLAGS) -c -o $@ $<

noawareness: $(OFILES) $(MD5_OBJ)
	$(CC) $(CFLAGS) $(LFLAGS) $(OFILES) $(MD5_OBJ) -o $@ $(LIBS)

clean:
	rm -rf $(BUILD_DIR)/*.o $(MD5_OBJ) noawareness *~
