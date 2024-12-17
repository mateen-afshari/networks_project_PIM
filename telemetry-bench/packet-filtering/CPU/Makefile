# Compiler
CXX := g++

# Compiler flags
<<<<<<< Updated upstream
CXXFLAGS := -Wall -Wextra -Werror -std=c++17 -O3 -fopenmp -lpcap
=======
CXXFLAGS := -Wall -Wextra -Werror -std=c++17 -O3 -fopenmp
>>>>>>> Stashed changes

# Executable name
EXEC := filter.out

# Source files
SRC_FILES := $(wildcard *.cpp)


.PHONY: all clean

all: $(EXEC)

$(EXEC): $(SRC_FILES) |
<<<<<<< Updated upstream
	$(CXX) $(CXXFLAGS) -o $@ $^
=======
	$(CXX) $(CXXFLAGS) -o $@ $^ -lpcap
>>>>>>> Stashed changes

clean:
	rm -rf $(EXEC)