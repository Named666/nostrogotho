#!/bin/bash
# Build script for nostrogotho
# Requirements: gcc, libwebsockets-dev, sqlite3-dev

gcc -std=c99 -Wall -Wextra -Wpedantic \
    src/main.c src/relay.c src/storage.c src/event.c src/filter.c src/nip.c src/log.c \
    -o nostrogotho \
    -lwebsockets -lsqlite3 -lpthread -lm

echo "Build complete: ./nostrogotho"
