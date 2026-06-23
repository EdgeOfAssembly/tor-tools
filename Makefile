# Makefile for tor_control + tor_top (modern C++23)
CXX = g++
CXXFLAGS = -std=c++23 -O2 -Wall -Wextra -Wpedantic -pthread

# tor_control: pure, no extra libs (uses local Tor control + sudo for privileged reads)
# tor_top: uses libcurl + jsoncpp for the reliable Onionoo API (matches the original working
#          behavior that produced rich data with countries and Mbit/s bandwidths).

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man/man1

all: tor_control tor_top

tor_control: tor_control.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

tor_top: tor_top.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< -lcurl $(shell pkg-config --cflags --libs jsoncpp 2>/dev/null || echo "")

install: all
	install -d $(BINDIR) $(MANDIR)
	install -m 755 tor_control $(BINDIR)/
	install -m 755 tor_top     $(BINDIR)/
	install -m 644 tor_control.1 $(MANDIR)/
	install -m 644 tor_top.1     $(MANDIR)/

clean:
	rm -f tor_control tor_top

.PHONY: all clean install run-control run-top
run-control: tor_control
	./tor_control --help

run-top: tor_top
	./tor_top --top 25 --interval 10
