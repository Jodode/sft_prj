#include <iostream>
#include <fstream>
#include <fmt/format.h>

#include "docopt.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"
#include "StatsCollector.h"
#include "Logger.h"

bool verboseMode = false;
static const char VERSION[] = "SFT v1.0";
static const char pathSeparator =
#if defined _WIN32 || defined __CYGWIN__ || defined WIN32
        '\\';
#else
        '/';
#endif

static const char USAGE[] =
R"(Signatures for traffic.

    Usage:
        sft [-v] -f INFILE
        sft [-v] -f INFILE -o OUTFILE
        sft (-h | --help)
        sft --version

    Options:
        -h --help               Show this screen.
        --version               Show version.
        -f INFILE               Path to input pcap/pcapng file.
        -o OUTFILE              Path to output report file.
        -v                      Verbose mode.
)";


inline bool fileExists (const std::string& name) {
    std::ifstream f(name.c_str());
    return f.good();
}

void collectPcap(pcpp::IFileReaderDevice* readerDevice, StatsCollector& stats) {
    pcpp::RawPacket rawPacket;
    while(readerDevice->getNextPacket(rawPacket)) {
        pcpp::Packet parsedPacket(&rawPacket);
        stats.collectPacket(parsedPacket);
    }
    if (verboseMode)
        std::cout << "[+] All packets collected" << std::endl ;

}

void writePayloadLen(size_t& max, std::vector<size_t>& packets, const std::string& protocol, std::ostream& output) {
    auto depth = static_cast<size_t>(std::log2(static_cast<double>(max)));
    std::vector<size_t> intervals(depth, 0);

    size_t countOfMaxes = 0;
    for (auto& len : packets) {
        if (len == 0)
            ++intervals[0];
        else {
            size_t upperBound = 20;
            for (size_t layer = 1; layer < depth + 2; ++layer) {
                if (len == max) {
                    ++countOfMaxes;
                }
                if (len < upperBound) {
                    ++intervals[layer];
                    break;
                }
                if (upperBound * 2 > max) {
                    upperBound = max + 1;
                } else { upperBound *= 2; }
            }
        }
    }

    output << fmt::format("|{:=^48}|\n|{:^16}{:^16}{:^16}|\n", protocol + " payload length", "interval", "count", "perc");
    output << fmt::format("|{:<16}{:<16}{:<16.3}|\n", 0, intervals[0], 100.0 * static_cast<float>(intervals[0]) /
                                                                       static_cast<float>(packets.size()));

    for (size_t lower_bound = 1, upper_bound = 20, i = 1; i < depth; lower_bound = upper_bound, upper_bound *= 2, ++i) {
        if (upper_bound > max) {
            upper_bound = max + 1;
            output << fmt::format("|{:<16}{:<16}{:<16.3}|\n", fmt::format("{}-{}", lower_bound, upper_bound-1),
                                  intervals[i], 100.0 * static_cast<double>(intervals[i]) /
                                                static_cast<double>(packets.size()));
            output << fmt::format("|{:<16}{:<16}{:<16.3}|\n", fmt::format("{}-max", max), countOfMaxes,
                                  100.0 * static_cast<double>(countOfMaxes) /
                                  static_cast<double>(packets.size()));
            break;
        } else {
            output << fmt::format("|{:<16}{:<16}{:<16.3}|\n", fmt::format("{}-{}", lower_bound, upper_bound-1),
                                  intervals[i], 100.0 * static_cast<double>(intervals[i]) /
                                                static_cast<double>(packets.size()));
        }
    }
}

void writeDstPorts(std::map<uint32_t, uint32_t>& dstMap, std::ostream& output) {
    output << fmt::format("|{:=^48}|\n|{:^16}{:^16}{:^16}|\n", "Dest port stats", "port", "count", "perc");
    size_t totalPortRequests = 0;
    for (auto& pair : dstMap)
        totalPortRequests += pair.second;


    for (auto& pair : dstMap) {
        double perc = 100.0 * static_cast<double>(pair.second) / static_cast<double>(totalPortRequests);
        if (perc > 5)
            output << fmt::format("|{:<16}{:<16}{:<16.3}|\n", pair.first, pair.second, perc);
    }
}

void writeDstIPv4(std::map<uint32_t, uint32_t>& dstMap, std::ostream& output) {
    output << fmt::format("|{:=^48}|\n|{:^16}{:^16}{:^16}|\n", "Dest IPv4 stats", "IPv4", "count", "perc");
    size_t totalIPv4 = 0;
    for (auto& pair : dstMap)
        totalIPv4 += pair.second;

    for (auto& pair : dstMap) {
        double perc = 100.0 * static_cast<double>(pair.second) / static_cast<double>(totalIPv4);
        if (perc > 5)
            output << fmt::format("|{:<16}{:<16}{:<16.3}|\n", pcpp::IPv4Address(pair.first).toString(), pair.second, perc);
    }
}

void writeResults(StatsCollector& stats, std::ostream& output) {
    if (stats.udpStats.numOfPackets > 0)
        writePayloadLen(stats.udpStats.udpMax, stats.udpStats.sizeOfPackets,  "UDP", output);
    if (stats.tcpStats.numOfPackets > 0)
        writePayloadLen(stats.tcpStats.tcpMax, stats.tcpStats.sizeOfPackets,  "TCP", output);
    if (!stats.dstPorts.empty())
        writeDstPorts(stats.dstPorts, output);
    if (!stats.dstIPv4.empty())
        writeDstIPv4(stats.dstIPv4, output);
    output << fmt::format("|{:=^48}|\n|{:^16}{:^16}{:^16}|\n", "Protocols distribution", "protocol", "count", "perc");
    output << fmt::format("|{:^16}{:<16}{:<16.3}|\n", "UDP", stats.udpStats.numOfPackets,
                          100.0 * static_cast<double>(stats.udpStats.numOfPackets) /
                            static_cast<double>(stats.totalPackets - stats.droppedPackets));
    output << fmt::format("|{:^16}{:<16}{:<16.3}|\n", "TCP", stats.tcpStats.numOfPackets,
                          100.0 * static_cast<double>(stats.tcpStats.numOfPackets) /
                          static_cast<double>(stats.totalPackets - stats.droppedPackets));

}

int main(int argc, char* argv[]) {
    std::map<std::string, docopt::value> args
            = docopt::docopt(USAGE,
                             { argv + 1, argv + argc },
                             true,
                             VERSION);

    verboseMode = args.find("-v")->second.asBool();

    StatsCollector statsCollector;

    if (args.find("-f")->second) {
        std::string inPath = args.find("-f")->second.asString();
        std::string inFilename = inPath.substr(inPath.rfind(pathSeparator) + 1);
        pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(inPath);

        if (reader == nullptr)
        {
            std::cerr << "[-] ERROR: Cannot determine reader for file type" << std::endl;
            return 1;
        }
        if (!reader->open())
        {
            std::cerr << "[-] ERROR: Cannot open " << inFilename << " for reading" << std::endl;
            return 1;
        }

        std::cout << "[+] File successfully opened" << std::endl;
        if (verboseMode)
            std::cout << "[+] Starting analyze" << std::endl;

        collectPcap(reader, statsCollector);
        std::cout << "[+] Writing report" << std::endl;
        if (args.find("-o")->second) {
            std::string outFilename = args.find("-o")->second.asString();
            if (fileExists(outFilename)) {
                std::cerr << "[-] ERROR: Output file exists" << std::endl;
                return 1;
            }
            std::ofstream outputFile;
            outputFile.open(outFilename, std::ios::out);
            writeResults(statsCollector, outputFile);
        } else {
            writeResults(statsCollector, std::cout);
        }
    }


    return 0;
}