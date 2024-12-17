#include <pcap.h>
#include <iostream>
#include <vector>
#include <map>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <cassert>
#include "../../util.h" // Utility for PIM setup
#include "libpimeval.h" // PIM library

using namespace std;

void calculateRTT(uint64_t maxPackets, vector<int> &synSecs, vector<int> &synUsecs,
                  vector<int> &ackSecs, vector<int> &ackUsecs, int64_t &sumRTT)
{
    // Allocate PIM objects for timestamps
    PimObjId synSec_pim = pimAlloc(PIM_ALLOC_AUTO, maxPackets, PIM_INT32);
    PimObjId synUsec_pim = pimAllocAssociated(synSec_pim, PIM_INT32);
    PimObjId ackSec_pim = pimAllocAssociated(synSec_pim, PIM_INT32);
    PimObjId ackUsec_pim = pimAllocAssociated(synSec_pim, PIM_INT32);
    PimObjId rtt_pim = pimAllocAssociated(synSec_pim, PIM_INT32);

    if (synSec_pim == -1 || synUsec_pim == -1 || ackSec_pim == -1 || ackUsec_pim == -1 || rtt_pim == -1)
    {
        cerr << "PIM allocation failed!" << endl;
        return;
    }

    // Copy timestamp data to PIM
    pimCopyHostToDevice(synSecs.data(), synSec_pim);
    pimCopyHostToDevice(synUsecs.data(), synUsec_pim);
    pimCopyHostToDevice(ackSecs.data(), ackSec_pim);
    pimCopyHostToDevice(ackUsecs.data(), ackUsec_pim);

    // Calculate RTT on PIM
    pimSub(ackSec_pim, synSec_pim, rtt_pim);       // RTT_sec = ackSec - synSec
    pimMulScalar(rtt_pim, rtt_pim, 1000);          // RTT_sec * 1000 (convert to ms)
    pimSub(ackUsec_pim, synUsec_pim, ackUsec_pim); // RTT_usec = ackUsec - synUsec
    pimDivScalar(ackUsec_pim, ackUsec_pim, 1000);  // RTT_usec / 1000
    pimAdd(rtt_pim, ackUsec_pim, rtt_pim);         // RTT_final = RTT_sec + RTT_usec

    // Perform reduction to calculate the sum of RTTs
    PimStatus status = pimRedSumInt(rtt_pim, &sumRTT);
    if (status != PIM_OK)
    {
        cerr << "PIM reduction failed!" << endl;
    }

    // Free PIM resources
    pimFree(synSec_pim);
    pimFree(synUsec_pim);
    pimFree(ackSec_pim);
    pimFree(ackUsec_pim);
    pimFree(rtt_pim);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        cerr << "Usage: " << argv[0] << " <pcap_file>" << endl;
        return 1;
    }

    const char *filename = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(filename, errbuf);

    if (pcap == nullptr)
    {
        cerr << "Error opening file: " << errbuf << endl;
        return 1;
    }

    if (!createDevice(nullptr))
    {
        cerr << "Failed to initialize PIM device." << endl;
        return 1;
    }

    const int maxPackets = 1000;
    map<uint32_t, struct timeval> synTimestamps;
    vector<int> synSecs, synUsecs, ackSecs, ackUsecs;

    struct pcap_pkthdr *header;
    const u_char *data;

    cout << "Processing packets from file: " << filename << endl;

    while (pcap_next_ex(pcap, &header, &data) >= 0 && synSecs.size() < maxPackets)
    {
        const struct ether_header *ethHeader = (struct ether_header *)data;
        if (ntohs(ethHeader->ether_type) != ETHERTYPE_IP)
            continue;

        const struct ip *ipHeader = (struct ip *)(data + sizeof(struct ether_header));
        if (ipHeader->ip_p != IPPROTO_TCP)
            continue;

        const struct tcphdr *tcpHeader = (struct tcphdr *)(data + sizeof(struct ether_header) + ipHeader->ip_hl * 4);

        uint32_t seqNum = ntohl(tcpHeader->th_seq);
        uint32_t ackNum = ntohl(tcpHeader->th_ack);

        if (tcpHeader->th_flags & TH_SYN)
        {
            synTimestamps[seqNum] = header->ts;
        }
        else if (tcpHeader->th_flags & TH_ACK && synTimestamps.find(ackNum - 1) != synTimestamps.end())
        {
            struct timeval synTime = synTimestamps[ackNum - 1];

            synSecs.push_back(synTime.tv_sec);
            synUsecs.push_back(synTime.tv_usec);
            ackSecs.push_back(header->ts.tv_sec);
            ackUsecs.push_back(header->ts.tv_usec);

            synTimestamps.erase(ackNum - 1);
        }
    }

    int64_t totalRTT = 0;
    calculateRTT(synSecs.size(), synSecs, synUsecs, ackSecs, ackUsecs, totalRTT);

    cout << "\nTotal RTT (sum) calculated using PIM: " << totalRTT << " ms" << endl;

    pimShowStats();
    pimDeleteDevice();
    pcap_close(pcap);

    return 0;
}
