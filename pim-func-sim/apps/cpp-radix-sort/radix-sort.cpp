// Radix Sort implementation on bitSIMD
// Copyright 2024 LavaLab @ University of Virginia. All rights reserved.

#include "libpimsim.h"
#include "../util.h"
#include <iostream>
#include <vector>
#include <getopt.h>

#include <cstdlib>
#include <time.h> 
#include <algorithm>
#include <chrono>
using namespace std;
using namespace std::chrono;

std::chrono::duration<double, std::milli> hostElapsedTime = std::chrono::duration<double, std::milli>::zero();

// Params ---------------------------------------------------------------------
typedef struct Params
{
  uint64_t numInputValue;
  char *configFile;
  char *inputFile;
  bool shouldVerify;
} Params;


void usage()
{
  fprintf(stderr,
          "\nUsage:  ./radix-sort [options]"
          "\n"
          "\n    -n    number of input values (default=65536 elements)"
          "\n    -c    dramsim config file"
          "\n    -i    input file containing the array of value to be sort (default=generates datapoints with random numbers)"
          "\n    -v    t = verifies PIM output with host output. (default=true)"
          "\n");
}

struct Params getInputParams(int argc, char **argv)
{
  struct Params p;
  p.numInputValue = 65536;
  p.configFile = nullptr;
  p.inputFile = nullptr;
  p.shouldVerify = true;

  int opt;
  while ((opt = getopt(argc, argv, "h:n:d:k:r:c:i:v:")) >= 0)
  {
    switch (opt)
    {
    case 'h':
      usage();
      exit(0);
      break;
    case 'n':
      p.numInputValue = strtoull(optarg, NULL, 0);
      break;
    case 'c':
      p.configFile = optarg;
      break;
    case 'i':
      p.inputFile = optarg;
      break;
    case 'v':
      p.shouldVerify = (*optarg == 't') ? true : false;
      break;
    default:
      fprintf(stderr, "\nUnrecognized option!\n");
      usage();
      exit(0);
    }
  }
  return p;
}

int main(int argc, char *argv[])
{
    struct Params params = getInputParams(argc, argv);

    std::cout << "PIM test: Radix Sort" << std::endl;

    if (!createDevice(params.configFile)){
        return 1;
    }

    unsigned numElements = params.numInputValue;
    //parameters that can be changed to explore design space
    unsigned bitsPerElement = 32;
    unsigned radix_bits = 8;
    unsigned num_passes = bitsPerElement / radix_bits;
    unsigned radix = 1 << radix_bits;

    //Allocating Pimobj for all the iterations
    std::vector<PimObjId> src_obj(num_passes);
    std::vector<PimObjId> compare_obj(num_passes);
    std::vector<PimObjId> compare_results_obj(num_passes);

    //What is the difference between bitsPerElement and PIM_INT32
    for(unsigned i = 0; i < num_passes; i++){
        src_obj[i] = pimAlloc(PIM_ALLOC_V1, numElements, bitsPerElement, PIM_INT32);
        if (src_obj[i] == -1) {
            std::cout << "Abort" << std::endl;
            return 1;
        }
    }
    for(unsigned i = 0; i < num_passes; i++){
        compare_obj[i] = pimAllocAssociated(PIM_ALLOC_V1, numElements, bitsPerElement, src_obj[i], PIM_INT32);
        if (compare_obj[i] == -1) {
            std::cout << "Abort" << std::endl;
            return 1;
        }
    }
    for(unsigned i = 0; i < num_passes; i++){
        compare_results_obj[i] = pimAllocAssociated(PIM_ALLOC_V1, numElements, bitsPerElement, src_obj[i], PIM_INT32);
        if (compare_results_obj[i] == -1) {
            std::cout << "Abort" << std::endl;
            return 1;
        }
    }

    //vectore for host use
    std::vector<int> src1(numElements);
    std::vector<int> dest(numElements);
    //array used to check result
    std::vector<int> sorted_array(numElements);
    //counting table in host
    std::vector<int> count_table(radix);
    
    //Assign random initial values to the input array
    getVector(params.numInputValue, src1);

    sorted_array = src1;

    unsigned mask = 0x000000FF;
    auto duration_cpu = high_resolution_clock::now() - high_resolution_clock::now();//initialize it to be 0

    //Outer iteration of radix sort, each iteration perform a counting sort
    // auto start_total = high_resolution_clock::now();
    for (unsigned i = 0; i < num_passes; i++){
        std::fill(count_table.begin(), count_table.end(), 0);

        //Create a slice of 'radix_bits' of the input array and only copy that array to bitSIMD
        std::vector<unsigned> src1_slice(numElements);  //shoud be an array of 8-bit elements if radix_bits=8
        for (unsigned j = 0; j < numElements; j++){
            src1_slice[j] = src1[j] & mask; //get the slices of all elements in the array
        }

        PimStatus status = pimCopyHostToDevice(PIM_COPY_V, (void*)src1_slice.data(), src_obj[i]);
        if (status != PIM_OK) {
            std::cout << "Abort" << std::endl;
            return 1;
        }

        //loop to count the occurance of all the possible number in sliced bit
        for (unsigned j = 0; j < radix; j++){
            unsigned brdcast_value = (j << (i * radix_bits)) & mask;
            status = pimBroadcast(compare_obj[i], brdcast_value);
            if (status != PIM_OK) {
                std::cout << "Abort" << std::endl;
                return 1;
            }

            status = pimEQ(src_obj[i], compare_obj[i], compare_results_obj[i]);
            if (status != PIM_OK) {
                std::cout << "Abort" << std::endl;
                return 1;
            }

            status = pimRedSumRanged(compare_results_obj[i], 0, numElements, &count_table[j]);
            if (status != PIM_OK) {
                std::cout << "Abort" << std::endl;
                return 1;
            }
        }

        //Assuming the BitSIMD support 8 bits EQ, so CPU doesn't need to creat slice
        auto start_cpu = high_resolution_clock::now();
        //host do prefix scan on the counting table
        for (unsigned j = 1; j < radix; j++){
            count_table[j] = count_table[j] + count_table[j-1];
        }

        //host perform reording on temp_array and copy it to src1
        std::vector<int> temp_array(numElements);

        for(int j = (int)(numElements - 1); j >= 0; j--){
            unsigned element_num = (src1[j] & mask) >> (i * radix_bits);
            temp_array[count_table[element_num]-1] = src1[j];
            count_table[element_num]--;
        }
        src1 = temp_array;

        auto stop_cpu = high_resolution_clock::now();
        duration_cpu += (stop_cpu - start_cpu);

        //shift mask bit for next iteration
        mask = mask << radix_bits;
    }

    // auto stop_total = high_resolution_clock::now();
    // auto duration_total = duration_cast<microseconds>(stop_total - start_total);
    hostElapsedTime = duration_cast<nanoseconds>(duration_cpu);
    
    // std::cout << "Total execution time = " << duration_total.count() / 1000 << "ms" << std::endl;
    // std::cout << "CPU execution time = " << duration_cpu_total.count() / 1000 << "us" << std::endl;

    // !check results and print it like km
    
    
    pimShowStats();

    if (params.shouldVerify){
        bool ok = true;
        std::sort(sorted_array.begin(), sorted_array.end());
        if(sorted_array != src1){
            std::cout << "Wrong answer!" << std::endl;
            ok = false;
        }
        if (ok) {
            std::cout << "All correct!" << std::endl;
        }
    }

    cout << "Host elapsed time: " << std::fixed << std::setprecision(3) << hostElapsedTime.count() << " ns." << endl;

    return 0;
}
