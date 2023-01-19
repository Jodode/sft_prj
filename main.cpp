#include <iostream>
#include <fmt/format.h>

#include "docopt.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"
#include "StatsCollector.h"

bool verboseMode = false;
double minimalPercPort = 5.0;
double minimalPercIP = 5.0;
std::string fileFormat = "txt";

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
        sft [-v] -f INFILE [--config CONFIG]
        sft [-v] -f INFILE -o OUTFILE [--config CONFIG]
        sft (-h | --help)
        sft --version

    Options:
        -h --help               Show this screen.
        --version               Show version.
        -f INFILE               Path to input pcap/pcapng file.
        -o OUTFILE              Path to output report file.
        -v                      Verbose mode.
        --config CONFIG         Config file.
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

    output << fmt::format((fileFormat == "csv" ? "{}\n{},{},{}\n" : "|{:=^48}|\n|{:^16}{:^16}{:^16}|\n"),
                          protocol + " payload length", "interval", "count", "perc");
    output << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:<16}{:<16}{:<16.3}|\n"), 0, intervals[0],
                          100.0 * static_cast<float>(intervals[0]) / static_cast<float>(packets.size()));
    for (size_t lower_bound = 1, upper_bound = 20, i = 1; i < depth; lower_bound = upper_bound, upper_bound *= 2, ++i) {

        double perc = 100.0 * static_cast<double>(intervals[i]) / static_cast<double>(packets.size());
        double percMax = 100.0 * static_cast<double>(countOfMaxes) / static_cast<double>(packets.size());
        if (upper_bound > max) {
            upper_bound = max + 1;

            output << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:<16}{:<16}{:<16.3}|\n"),
                                  fmt::format("{}-{}", lower_bound, upper_bound-1), intervals[i], perc);
            output << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:<16}{:<16}{:<16.3}|\n"),
                                  fmt::format("{}-max", max), countOfMaxes, percMax);
            break;
        } else {
            output << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:<16}{:<16}{:<16.3}|\n"),
                                  fmt::format("{}-{}", lower_bound, upper_bound-1), intervals[i], perc);
        }
    }
}

void writeDstPorts(std::map<uint32_t, uint32_t>& dstMap, std::ostream& output) {

    output << fmt::format((fileFormat == "csv" ? "{}\n{},{},{}\n" : "|{:=^48}|\n|{:^16}{:^16}{:^16}|\n"),
                                "Dest port stats", "port", "count", "perc");

    size_t totalPortRequests = 0;
    for (auto& pair : dstMap)
        totalPortRequests += pair.second;


    for (auto& pair : dstMap) {
        double perc = 100.0 * static_cast<double>(pair.second) / static_cast<double>(totalPortRequests);
        if (perc > minimalPercPort)
            output << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:<16}{:<16}{:<16.3}|\n"),
                                  pair.first, pair.second, perc);
    }
}

void writeDstIPv4(std::map<uint32_t, uint32_t>& dstMap, std::ostream& output) {
    output << fmt::format((fileFormat == "csv" ? "{}\n{},{},{}\n" : "|{:=^48}|\n|{:^16}{:^16}{:^16}|\n"),
                          "Dest IPv4 stats", "IPv4", "count", "perc");
    size_t totalIPv4 = 0;
    for (auto& pair : dstMap)
        totalIPv4 += pair.second;

    for (auto& pair : dstMap) {
        double perc = 100.0 * static_cast<double>(pair.second) / static_cast<double>(totalIPv4);
        if (perc > minimalPercIP)
            output << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:<16}{:<16}{:<16.3}|\n"),
                                  pcpp::IPv4Address(pair.first).toString(), pair.second, perc);
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
    output << fmt::format((fileFormat == "csv" ? "{}\n{},{},{}\n" : "|{:=^48}|\n|{:^16}{:^16}{:^16}|\n"),
                          "Protocols distribution", "protocol", "count", "perc");
    output << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:^16}{:<16}{:<16.3}|\n"), "UDP",
                          stats.udpStats.numOfPackets,
                            100.0 * static_cast<double>(stats.udpStats.numOfPackets) /
                                static_cast<double>(stats.udpStats.numOfPackets + stats.tcpStats.numOfPackets));
    output << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:^16}{:<16}{:<16.3}|\n"), "TCP",
                          stats.tcpStats.numOfPackets,
                            100.0 * static_cast<double>(stats.tcpStats.numOfPackets) /
                                static_cast<double>(stats.udpStats.numOfPackets + stats.tcpStats.numOfPackets));

}

int main(int argc, char* argv[]) {
    std::map<std::string, docopt::value> args
            = docopt::docopt(USAGE,
                             { argv + 1, argv + argc },
                             true,
                             VERSION);

    verboseMode = args.find("-v")->second.asBool();

    if (args.find("--config")->second) {
        std::string pathConfig = args.find("--config")->second.asString();
        std::string config = pathConfig.substr(pathConfig.rfind(pathSeparator) + 1);
        if (!fileExists(pathConfig)) {
            std::cerr << "[-] Config file not exists";
            return 1;
        }
        std::ifstream configFile (pathConfig);
        std::string line;
        if (configFile.is_open()) {
            while (std::getline(configFile, line)) {
                if (line[0] != '#'){
                    std::istringstream sin(line.substr(line.find('=') + 1));
                    if (line.find("MINIMAL_PORT_PERC") != -1)
                        sin >> minimalPercPort;
                    else if (line.find("MINIMAL_IP_PERC") != -1)
                        sin >> minimalPercIP;
                }
            }
        }
        configFile.close();
        if (verboseMode)
            std::cout << "[+] Config file read";
    }

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
            if (outFilename.substr(outFilename.find_last_of('.') + 1) == "csv") fileFormat = "csv";
            std::ofstream outputFile;
            outputFile.open(outFilename, std::ios::out);
            writeResults(statsCollector, outputFile);
            outputFile.close();
        } else {
            writeResults(statsCollector, std::cout);
        }
    }


    return 0;
}