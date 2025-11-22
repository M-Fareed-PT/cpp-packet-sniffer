#include <pcap.h>
#include <iostream>
#include <unordered_map>
#include <csignal>
#include <cstring>
#include <netinet/in.h> // For ntohs
#include <arpa/inet.h> // inet_ntoa
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

static bool keep_running = true;
void sigint_handler(int) { keep_running = false; }

struct Stats {
    uint64_t total = 0;
    uint64_t ether = 0;
    uint64_t ipv4 = 0;
    uint64_t tcp = 0;
    uint64_t udp = 0;
    uint64_t icmp = 0;
};

Stats stats;
std::unordered_map<std::string, uint64_t> talkers;

void packet_handler(u_char* /*user*/, const struct pcap_pkthdr* header, const u_char* packet) {
    stats.total++;
    stats.ether++;

    if (header->caplen < sizeof(ether_header)) return;
    const ether_header* eth = (const ether_header*)packet;
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        stats.ipv4++;
        const u_char* ip_pkt = packet + sizeof(ether_header);
        const ip* iphdr = (const ip*)ip_pkt;
        char src[INET_ADDRSTRLEN];
        char dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iphdr->ip_src, src, sizeof(src));
        inet_ntop(AF_INET, &iphdr->ip_dst, dst, sizeof(dst));
        talkers[std::string(src)]++;
        uint8_t proto = iphdr->ip_p;
        if (proto == IPPROTO_TCP) {
            stats.tcp++;
        } else if (proto == IPPROTO_UDP) {
            stats.udp++;
        } else if (proto == IPPROTO_ICMP) {
            stats.icmp++;
        }
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, sigint_handler);
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* dev = nullptr;

    if (argc >= 2) dev = argv[1];

    if (!dev) {
        dev = pcap_lookupdev(errbuf);
        if (!dev) {
            std::cerr << "No device found: " << errbuf << "\n";
            return 1;
        }
    }

    pcap_t* handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << "\n";
        return 1;
    }

    std::cout << "Listening on device: " << dev << "\nPress Ctrl-C to stop...\n";

    while (keep_running) {
        pcap_dispatch(handle, 10, packet_handler, nullptr);
        // Periodically print stats
        static int ticks = 0;
        if (++ticks % 50 == 0) {
            std::cout << "Total: " << stats.total
                      << " | IPv4: " << stats.ipv4
                      << " | TCP: " << stats.tcp
                      << " | UDP: " << stats.udp
                      << " | ICMP: " << stats.icmp << "\n";
            // print top talkers
            std::vector<std::pair<uint64_t,std::string>> v;
            for (auto &p : talkers) v.push_back({p.second, p.first});
            sort(v.rbegin(), v.rend());
            std::cout << "Top talkers:\n";
            for (size_t i=0;i< std::min<size_t>(5,v.size());++i)
                std::cout << "  " << v[i].second << " -> " << v[i].first << "\n";
        }
    }

    pcap_close(handle);
    std::cout << "Stopped.\n";
    return 0;
}
