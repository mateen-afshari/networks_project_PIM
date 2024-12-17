PROJ_ROOT = ../../..
include ${PROJ_ROOT}/Makefile.common

# Enable OpenMP if specified
# Usage: make USE_OPENMP=1
USE_OPENMP ?= 0
ifeq ($(USE_OPENMP),1)
	CXXFLAGS += -fopenmp
endif

# Enable libpcap linking
LDFLAGS += -lpcap

# Executable and source files
EXEC := filter.out
SRCS := filter.cpp

# Targets
debug perf dramsim3_integ: $(EXEC)

$(EXEC): $(SRCS) $(DEPS)
	$(CXX) $(SRCS) $(CXXFLAGS) $(LDFLAGS) -o $@

clean:
	rm -rf $(EXEC) *.dSYM

