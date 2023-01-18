#include <map>
#include <sstream>
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "IPv4Layer.h"
#include "EthLayer.h"
#include "PayloadLayer.h"
#include "PacketUtils.h"
#include "SystemUtils.h"

void upsert(std::map<uint32_t, uint32_t> &map, uint32_t val){
    if (map.find(val) == map.end())
        map[val] = 1;
    else
        ++map[val];
}

struct GeneralStats {
    void clear() {
        numOfPackets = 0;
        amountOfPackets = 0;
        sizeOfPackets = std::vector<size_t>();
    }


    size_t numOfPackets{};
    uint64_t amountOfPackets{};
    std::vector<size_t> sizeOfPackets;
};

struct UDPStats : GeneralStats {
    size_t udpMax = 0;

    void update(pcpp::UdpLayer* udpLayer) {
        size_t length = udpLayer->getLayerPayloadSize();

        ++numOfPackets;
        if (length > udpMax) udpMax = length;
        amountOfPackets += length;
        sizeOfPackets.push_back(length);
    }
};
struct TCPStats : GeneralStats {
    size_t tcpMax = 0;

    void update(pcpp::TcpLayer* tcpLayer) {
        size_t length = tcpLayer->getLayerPayloadSize();

        ++numOfPackets;
        if (length > tcpMax) tcpMax = length;
        amountOfPackets += length;
        sizeOfPackets.push_back(length);
    }
};

struct StatsCollector {
    StatsCollector() { this->clear();}
    ~StatsCollector() = default;

    UDPStats udpStats;
    TCPStats tcpStats;
    size_t totalPackets{};
    size_t droppedPackets{};
    std::map<uint32_t, uint32_t> dstPorts;
    std::map<uint32_t, uint32_t> dstIPv4;

    void clear() {
        udpStats.clear();
        tcpStats.clear();
        totalPackets = 0;
        droppedPackets = 0;
        dstPorts = std::map<uint32_t, uint32_t>();
    }

    void collectPacket (pcpp::Packet &packet) {
        ++totalPackets;
        uint32_t port(0);
        if (packet.isPacketOfType(pcpp::TCP)) {
            auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>();
            tcpStats.update(tcp);
            port = tcp->getDstPort();

        }
        if (packet.isPacketOfType(pcpp::UDP)) {
            auto* udp = packet.getLayerOfType<pcpp::UdpLayer>();
            udpStats.update(udp);
            port = udp->getDstPort();
        } else {
            ++droppedPackets;
        }
        if (port) upsert(dstPorts, port);
        upsert(dstIPv4, packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address().toInt());

    }
};

struct StatsResult {};

