CC ?= cc
PKG_CONFIG ?= pkg-config
LUA_PACKAGE ?= lua5.4
CFLAGS ?= -O2
CFLAGS += -Wall -Wextra -Werror

TARGET := svrcrypto.so
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags libgcrypt)
GCRYPT_LIBS := $(shell $(PKG_CONFIG) --libs libgcrypt)
HOST_OS := $(shell uname -s)

ifeq ($(HOST_OS),Darwin)
LUA_PREFIX ?= $(shell brew --prefix lua@5.4)
CPPFLAGS += -I$(LUA_PREFIX)/include/lua5.4
LDFLAGS += -bundle -undefined dynamic_lookup
LUA_BIN ?= $(LUA_PREFIX)/bin/lua5.4
else
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags $(LUA_PACKAGE))
LUA_LIBS := $(shell $(PKG_CONFIG) --libs $(LUA_PACKAGE))
LDFLAGS += -shared $(LUA_LIBS)
LUA_BIN ?= lua5.4
endif

.PHONY: all test clean

all: $(TARGET)

$(TARGET): svrcrypto.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC $(LDFLAGS) -o $@ $< $(GCRYPT_LIBS)

test: $(TARGET)
	LUA_CPATH='./?.so;;' $(LUA_BIN) ../test/native/test_svrcrypto.lua

clean:
	rm -f $(TARGET)
