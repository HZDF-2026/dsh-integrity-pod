# dsh-integrity-pod C++17 port — bit-exact with the Node.js plugin reference.
# make / make all   build ../dist/cpp/dship-integrity(.exe)
# make test         build and run the golden-table tests
# make clean        remove build artifacts
#
# Directory commands are shell-guarded because mingw32-make without a POSIX
# shell cannot exec `mkdir`/`rm` directly; `cmd /c` is a real executable, so it
# works through CreateProcess as well as through any sh. Backslash path
# rewriting is Windows-only: on POSIX a literal `..\dist\cpp` is one oddly
# named directory and the link step dies on a missing output path.

CXX ?= g++
CXXSTD ?= -std=c++17
WARN ?= -Wall -Wextra -O2
BUILD := build
DIST := ../dist/cpp

SRCS := sha256.cpp jsfold.cpp jsprops.cpp jsjson.cpp jsre.cpp util.cpp store.cpp \
        prereg.cpp adjudicate.cpp provenance.cpp bitwin.cpp guardrail.cpp cli.cpp
LIB_SRCS := sha256.cpp jsfold.cpp jsprops.cpp jsjson.cpp jsre.cpp util.cpp store.cpp \
            prereg.cpp adjudicate.cpp provenance.cpp bitwin.cpp guardrail.cpp
OBJS := $(addprefix $(BUILD)/,$(SRCS:.cpp=.o))
LIB_OBJS := $(addprefix $(BUILD)/,$(LIB_SRCS:.cpp=.o))

BIN := $(DIST)/dship-integrity$(if $(filter $(OS),Windows_NT),.exe,)
TEST_BIN := $(BUILD)/test_golden$(if $(filter $(OS),Windows_NT),.exe,)

ifeq ($(OS),Windows_NT)
MD := cmd /d /c md
RMRF := cmd /d /c rmdir /s /q
FIXPATH = $(subst /,\,$1)
else
MD := mkdir -p
RMRF := rm -rf
FIXPATH = $1
endif

.PHONY: all test clean

all: $(BIN)

$(BIN): $(OBJS) | $(DIST)
	$(CXX) $(CXXSTD) $(WARN) -o $@ $^

$(DIST) $(BUILD):
	-$(MD) $(call FIXPATH,$@)

$(BUILD)/%.o: %.cpp | $(BUILD)
	$(CXX) $(CXXSTD) $(WARN) -c -o $@ $<

test: $(BIN) $(TEST_BIN)
	$(TEST_BIN)

$(TEST_BIN): test_golden.cpp $(LIB_OBJS) | $(BUILD)
	$(CXX) $(CXXSTD) $(WARN) -o $@ $^

clean:
	-$(RMRF) $(call FIXPATH,$(BUILD))
	-$(RMRF) $(call FIXPATH,$(DIST))
