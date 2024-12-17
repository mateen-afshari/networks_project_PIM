#include <iostream>
#include <vector>
#include <pcap.h>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <getopt.h>

#define MY_RANGE 1000

using namespace std;

/**
 * @brief Command-line parameter structure
 */
typedef struct Params
{
    char *pcapFile;
    uint64_t key;
    bool shouldVerify;
} Params;

/**
 * @brief Display program usage
 */
void usage()
{
    fprintf(stderr,
            "\nUsage:  ./filter.out [options]"
            "\n"
            "\n    -p    PCAP file containing packet data (required)"
            "\n    -k    Key value for filtering (default = 100)"
            "\n    -v    t = print the number of selected packets. (default=false)"
            "\n");
}

/**
 * @brief Parse command-line arguments
 */
struct Params getInputParams(int argc, char **argv)
{
    struct Params p;
    p.pcapFile = nullptr;
    p.key = 100;
    p.shouldVerify = false;

    int opt;
    while ((opt = getopt(argc, argv, "h:p:k:v:")) >= 0)
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

/**
 * @brief Main function
 */
int main(int argc, char **argv)
{
    struct Params p = getInputParams(argc, argv);

    // Open the PCAP file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(p.pcapFile, errbuf);
    if (handle == nullptr)
    {
        cerr << "Error opening PCAP file: " << errbuf << endl;
        return 1;
    }

    vector<uint64_t> packetSizes;
    struct pcap_pkthdr *header;
    const u_char *packet;

    // Extract packet sizes from the PCAP file
    while (pcap_next_ex(handle, &header, &packet) == 1)
    {
        packetSizes.push_back(header->caplen); // Add packet size
    }

    pcap_close(handle);

    uint64_t buffer_in_CPU = 0;
    uint64_t selectedNum = 0;

<<<<<<< Updated upstream
    // Cache flushing step
    uint64_t dummyVectorSize = 1073741824;
    vector<int> dummyVector1(dummyVectorSize, 0);
    for (uint64_t j = 0; j < dummyVectorSize; j++)
    {
        dummyVector1[j] += rand() % MY_RANGE;
    }
=======
>>>>>>> Stashed changes

    // Filter packets by key
    auto start = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsedTime;

    for (size_t i = 0; i < packetSizes.size(); i++)
    {
        if (p.key > packetSizes[i])
        {
            buffer_in_CPU += packetSizes[i];
            selectedNum++;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    elapsedTime = (end - start);

    if (p.shouldVerify)
    {
        cout << selectedNum << " out of " << packetSizes.size() << " packets selected" << endl;
    }
    cout << "Total size of selected packets: " << buffer_in_CPU << " bytes" << endl;
    cout << "Duration: " << std::fixed << std::setprecision(3) << elapsedTime.count() << " ms." << endl;
    cout << endl;

    return 0;
}
