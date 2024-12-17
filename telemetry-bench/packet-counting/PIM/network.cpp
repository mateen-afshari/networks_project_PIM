<<<<<<< Updated upstream
// Copyright (c) 2024 University of Virginia
// This file is licensed under the MIT License.
// See the LICENSE file in the root of this repository for more details.
=======
>>>>>>> Stashed changes

#include <iostream>
#include <vector>
#include <getopt.h>
#include <stdint.h>
#include <iomanip>
#include <cassert>
#include <pcap.h>
#include <cstring>
#include <netinet/ip.h>  // IP header
#include <netinet/tcp.h> // TCP header
#include <netinet/udp.h> // UDP header
#include <netinet/ether.h> // Ethernet header
#if defined(_OPENMP)
#include <omp.h>
#endif

#include "../../util.h"
#include "libpimeval.h"

using namespace std;

// Params ---------------------------------------------------------------------
typedef struct Params
{
  uint64_t vectorLength;
  char *configFile;
  char *inputFile;
  bool shouldVerify;
} Params;

struct Packet {
  struct pcap_pkthdr header;
  std::vector<uint8_t> data;
};


class NetworkPimDevice {
    public:
        int flowCount;
        PimObjId src_pim;
        PimObjId inc_pim;

        NetworkPimDevice(int count) {
            flowCount = count;

            src_pim = pimAlloc(PIM_ALLOC_AUTO, flowCount, PIM_INT32);
            assert(src_pim != -1);

            inc_pim = pimAllocAssociated(src_pim, PIM_INT32);
            assert(inc_pim != -1);

            pimBroadcastUInt(inc_pim, 1);
        }
        void increment() {
            pimAdd(src_pim, inc_pim, src_pim);
        }
        int returnCount() {
            int ret = 0;
            pimCopyDeviceToHost(src_pim, &ret);
            return ret;
        }
};


void usage()
{
  fprintf(stderr,
          "\nUsage:  ./scale.out [options]"
          "\n"
          "\n    -l    input size (default=2048 elements)"
          "\n    -c    dramsim config file"
          "\n    -i    input file containing one vector (default=generates vector with random numbers)"
          "\n    -v    t = verifies PIM output with host output. (default=false)"
          "\n");
}

struct Params getInputParams(int argc, char **argv)
{
  struct Params p;
  p.vectorLength = 2048;
  p.configFile = nullptr;
  p.inputFile = nullptr;
  p.shouldVerify = false;

  int opt;
  while ((opt = getopt(argc, argv, "h:l:c:i:v:")) >= 0)
  {
    switch (opt)
    {
    case 'h':
      usage();
      exit(0);
      break;
    case 'l':
      p.vectorLength = strtoull(optarg, NULL, 0);
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

void printPacketDetails(const Packet& packet) {
    const uint8_t* packet_data = packet.data.data();

    // Parse Ethernet header
    struct ether_header* eth_header = (struct ether_header*)packet_data;
    std::cout << "Source MAC: ";
    for (int i = 0; i < 6; i++) std::cout << std::hex << (int)eth_header->ether_shost[i] << (i < 5 ? ":" : "");
    std::cout << "\nDestination MAC: ";
    for (int i = 0; i < 6; i++) std::cout << std::hex << (int)eth_header->ether_dhost[i] << (i < 5 ? ":" : "");
    std::cout << std::dec << std::endl;

    // Parse IP header if Ethernet type is IP (0x0800)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip* ip_header = (struct ip*)(packet_data + sizeof(struct ether_header));
        std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

        // Check if protocol is TCP or UDP
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + sizeof(struct ether_header) + ip_header->ip_hl * 4);
            std::cout << "Source Port: " << ntohs(tcp_header->source) << std::endl;
            std::cout << "Destination Port: " << ntohs(tcp_header->dest) << std::endl;
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr* udp_header = (struct udphdr*)(packet_data + sizeof(struct ether_header) + ip_header->ip_hl * 4);
            std::cout << "Source Port: " << ntohs(udp_header->source) << std::endl;
            std::cout << "Destination Port: " << ntohs(udp_header->dest) << std::endl;
        }
    }
}

void scale(uint64_t vectorLength, const std::vector<int> &src_host, int A, std::vector<int> &dst_host)
{

//  PimObjId dst_pim = pimAllocAssociated(src_pim, PIM_INT32);
  //assert(dst_pim != -1);

//  PimStatus status = pimCopyHostToDevice((void *)src_host.data(), src_pim);
  //assert (status == PIM_OK);

  //status = pimMulScalar(src_pim, dst_pim, A);
  //assert (status == PIM_OK);

  //dst_host.resize(vectorLength);
  //status = pimCopyDeviceToHost(dst_pim, (void *)dst_host.data());
  //assert (status == PIM_OK);

 // pimFree(src_pim);
  //pimFree(dst_pim);
}

int main(int argc, char* argv[])
{
  struct Params params = getInputParams(argc, argv);
  std::cout << "Running PIM network: " << params.vectorLength << "\n";
  std::vector<int> X, Y_device;
  if (params.inputFile == nullptr)
  {
  } 
  else 
  {
    std::cout << "Reading from input file is not implemented yet." << std::endl;
    return 1;
  }
  
  if (!createDevice(params.configFile))
  {
    return 1;
  }

  //TODO: Check if vector can fit in one iteration. Otherwise need to run in multiple iteration.
  //scale(params.vectorLength, X, A, Y_device);

    
  int flowCountSize = 1;
<<<<<<< Updated upstream
  const char* filename = "smallFlows.pcap";
=======
  const char* filename = "../../smallFlows.pcap";
>>>>>>> Stashed changes
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* pcap = pcap_open_offline(filename, errbuf);

  if (pcap == nullptr) {
    std::cerr << "Error opening file: " << errbuf << std::endl;
        return 1;
  }
  std::vector<Packet> packets;  // Vector to store packets
  struct pcap_pkthdr* header;
  const uint8_t* data;

  NetworkPimDevice device = NetworkPimDevice(flowCountSize);
<<<<<<< Updated upstream

  while (int ret = pcap_next_ex(pcap, &header, &data) >= 0) {
      Packet packet;
      packet.header = *header;  // Copy the header
      packet.data.resize(header->caplen);
      memcpy(packet.data.data(), data, header->caplen);  // Copy the data
      //std::cout << packet.header << "\n";
      packets.push_back(packet);  // Store the packet in memory
      device.increment();
=======
  int count = 0;


  while (int ret = pcap_next_ex(pcap, &header, &data) >= 0 && count < 1000)
  {                      
    device.increment();
    count ++;
>>>>>>> Stashed changes
  }


  //printPacketDetails(packets[0]);
  cout << "pim count: " << device.returnCount() << "vs vector length: " << packets.size() << "\n";
  //cout << packets.size() << "\n";
  if (params.shouldVerify) 
  {
    
  }

  pimShowStats();

  return 0;
}
