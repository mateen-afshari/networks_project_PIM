#include "libpimeval.h"
#include "../../util.h"
#include <iostream>
#include <vector>
#include <pcap.h>
#include <getopt.h>
#include <cstdlib>
#include <chrono>
#include <cstring>
#include <iomanip>

#define MY_RANGE 1000

using namespace std;

typedef struct Params
{
    char *pcapFile;
    uint64_t key;
    char *configFile;
    bool shouldVerify;
} Params;

void usage()
{
    fprintf(stderr,
            "\n    Usage:  ./filter.out [options]"
            "\n"
            "\n    -p    PCAP file containing packet data (required)"
            "\n    -k    value of key (default = 100)"
            "\n    -c    dramsim config file"
            "\n    -v    t = verifies PIM output with host output. (default=true)"
            "\n");
}

struct Params getInputParams(int argc, char **argv)
{
    struct Params p;
    p.pcapFile = nullptr;
    p.key = 100;
    p.configFile = nullptr;
    p.shouldVerify = true;

    int opt;
    while ((opt = getopt(argc, argv, "h:p:k:c:v:")) >= 0)
    {
        switch (opt)
        {
        case 'h':
            usage();
            exit(0);
            break;
        case 'p':
            p.pcapFile = optarg;
            break;
        case 'k':
            p.key = strtoull(optarg, NULL, 0);
            break;
        case 'c':
            p.configFile = optarg;
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
    if (!p.pcapFile)
    {
        fprintf(stderr, "Error: PCAP file is required.\n");
        usage();
        exit(1);
    }
    return p;
}

bool extractPacketSizes(const char *pcapFile, vector<uint64_t> &inVector)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcapFile, errbuf);
    if (handle == nullptr)
    {
        cerr << "Error opening PCAP file: " << errbuf << endl;
        return false;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;

    while (pcap_next_ex(handle, &header, &packet) == 1)
    {
        inVector.push_back(header->caplen); // Add packet size to the vector
    }

    pcap_close(handle);
    return true;
}

int main(int argc, char **argv)
{
    struct Params p = getInputParams(argc, argv);
    cout << "PIM test: database-filtering with PCAP input" << endl;

    vector<uint64_t> inVector;

    // Extract packet sizes from the PCAP file
    if (!extractPacketSizes(p.pcapFile, inVector))
    {
        return 1;
    }

    uint64_t inVectorSize = inVector.size();
    uint64_t key = p.key;

    cout << "Number of packets: " << inVectorSize << endl;

    vector<uint64_t> bitMap(inVectorSize, 0);
    vector<int> bitMapHost(inVectorSize, 0);

    if (!createDevice(p.configFile))
    {
        return 1;
    }

    // PIM parameters
    PimObjId srcObj1 = pimAlloc(PIM_ALLOC_AUTO, inVector.size(), PIM_UINT64);
    if (srcObj1 == -1)
    {
        cerr << "Abort: Failed to allocate PIM object." << endl;
        return 1;
    }
    PimObjId srcObj2 = pimAllocAssociated(srcObj1, PIM_UINT64);
    if (srcObj2 == -1)
    {
        cerr << "Abort: Failed to allocate PIM object." << endl;
        return 1;
    }

    PimStatus status = pimCopyHostToDevice((void *)inVector.data(), srcObj1);
    if (status != PIM_OK)
    {
        cerr << "Abort: Failed to copy data to PIM." << endl;
        return 1;
    }

    status = pimLTScalar(srcObj1, srcObj2, key);
    if (status != PIM_OK)
    {
        cerr << "Abort: Failed to execute PIM comparison." << endl;
        return 1;
    }

    status = pimCopyDeviceToHost(srcObj2, (void *)bitMap.data());
    if (status != PIM_OK)
    {
        cerr << "Abort: Failed to copy result from PIM." << endl;
    }

    pimShowStats();
    pimFree(srcObj1);
    pimFree(srcObj2);

    // Filter and count selected packets
    uint64_t selectedNum = 0;
    uint64_t buffer_in_CPU = 0;

    auto start = chrono::high_resolution_clock::now();

    for (size_t i = 0; i < inVectorSize; i++)
    {
        if (bitMap[i] == 1)
        {
            buffer_in_CPU += inVector[i];
            selectedNum++;
        }
    }

    auto stop = chrono::high_resolution_clock::now();
    chrono::duration<double, milli> elapsedTime = stop - start;

    if (p.shouldVerify)
    {
        cout << selectedNum << " out of " << inVectorSize << " packets selected" << endl;
    }

    cout << "Total size of selected packets: " << buffer_in_CPU << " bytes" << endl;
    cout << "Host elapsed time: " << fixed << setprecision(3) << elapsedTime.count() << " ms." << endl;

    return 0;
}
