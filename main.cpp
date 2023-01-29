/**
 \file
 \brief Компилируемый файл со всем функционалом

 В этом файле описано всё взаимодействие между пользователем - программой и программой - системой

*/

#include <iostream>
#include <fmt/format.h>
#include <cstdlib>
#include "docopt.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"
#include "StatsCollector.h"
#include "EthLayer.h"
#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"

//! Режим работы программы false - тихий, true - подробный
bool verboseMode = false;
//! Минимальный процент содержания порта в трафике для отображения в статистике
double minimalPercPort = 5.0;
//! Минимальный процент содержания IP адреса в трафике для отображения в статистике
double minimalPercIP = 5.0;
//! Формат файла с результатом
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
        sft --test

    Options:
        -h --help               Show this screen.
        --version               Show version.
        -f INFILE               Path to input pcap/pcapng file.
        -o OUTFILE              Path to output report file.
        -v                      Verbose mode.
        --config CONFIG         Config file.
        --test         Testing.
)";

/**
 * \brief Функция проверки существования файла
 * \author Jodode
 * @param name путь до файла/имя
 */
inline bool fileExists (const std::string& name) {
    std::ifstream f(name.c_str());
    return f.good();
}

void require(std::string test_name, bool require_exp){
    if (require_exp) {
        std::cout << "[v] -- " << test_name << " -- " << "passed" << std::endl;
    } else {
        std::cout << "[x] -- " << test_name << " -- " << "failed" << std::endl;
    }
}
/**
 * \brief Функция для получения процентной статистики
 * @param totalValues количество определенных элементов в выборке
 * @param allValues количество всех элементов в выборке
 * @return Процент от общего количества
 */
double getPerc(const size_t& totalValues, const size_t& allValues) {
    return (static_cast<double>(totalValues) / static_cast<double>(allValues)) * 100.0;
}

double getPerc(const uint32_t & totalValues, const size_t& allValues) {
    return getPerc(static_cast<size_t>(totalValues), allValues);
}


/**
 * \brief Метод для сборки пакетов в хранилище статистики
 * \author Jodode
 * \version 0.1
 * @param readerDevice читающий агрегат
 * @param stats Хранилище статистики
 *
 * Метод итерируется по всем пакетам трафика и отправляет их на дальнейшую обработку в хранилище
 */
void collectPcap(pcpp::IFileReaderDevice* readerDevice, StatsCollector& stats) {
    pcpp::RawPacket rawPacket;
    while(readerDevice->getNextPacket(rawPacket)) {
        pcpp::Packet parsedPacket(&rawPacket);
        stats.collectPacket(parsedPacket);
    }
    if (verboseMode)
        std::cout << "[+] All packets collected" << std::endl ;

}


/**
 * \brief Метод для записи статистики "полезной нагрузки"
 * \author Jodode
 * \version 0.1
 * @param max Максимальный размер "полезной нагрузки" в пакетах протокола X (UDP/TCP)
 * @param packets Вектор с размерами "полезной нагрузки" пакетов протокола X (UDP/TCP)
 * @param protocol Протокол X (UDP/TCP)
 * @param output Поток для записи результатов
 *
 * Внутри метода высчитывается распределение пакетов по байт-интервалам, а затем результат записывается в указанный пользователем
 * поток, существует автоматическое определение формата вывода (csv,txt)
 */
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

                if (len < upperBound) {
                    if (len == max) {
                        ++countOfMaxes;
                    }
                    ++intervals[layer];
                    break;
                }
                if (upperBound * 2 > max) {
                    upperBound = max + 1;
                } else { upperBound *= 2; }
            }
        }
    }

    size_t totalPackets = packets.size();

    output << fmt::format((fileFormat == "csv" ? "{}\n{},{},{}\n" : "|{:=^48}|\n|{:^16}{:^16}{:^16}|\n"),
                          protocol + " payload length", "interval", "count", "perc");
    output << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:<16}{:<16}{:<16.3}|\n"), 0, intervals[0],
                          getPerc(intervals[0], totalPackets));
    for (size_t lower_bound = 1, upper_bound = 20, i = 1; i < depth; lower_bound = upper_bound, upper_bound *= 2, ++i) {

        double perc = getPerc(intervals[i], totalPackets);
        double percMax = getPerc(countOfMaxes, totalPackets);
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

/**
 * \brief Метод для записи статистики high-load портов
 * \author Jodode
 * \version 0.1
 * @param dstMap Словарь {port : countOfAddress}
 * @param output Поток для записи результатов
 *
 * Внутри метода высчитывается распределение портов в процентах, а затем результат записывается в указанный пользователем
 * поток, существует автоматическое определение формата вывода (csv,txt). Выводимые данные можно фильтровать с помощью
 * конфиг файла
 */
void writeDstPorts(std::map<uint32_t, uint32_t>& dstMap, std::ostream& output) {

    output << fmt::format((fileFormat == "csv" ? "{}\n{},{},{}\n" : "|{:=^48}|\n|{:^16}{:^16}{:^16}|\n"),
                                "Dest port stats", "port", "count", "perc");

    size_t totalPortRequests = 0;
    for (auto& pair : dstMap)
        totalPortRequests += pair.second;


    for (auto& pair : dstMap) {
        double perc = getPerc(pair.second, totalPortRequests);
        if (perc > minimalPercPort)
            output << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:<16}{:<16}{:<16.3}|\n"),
                                  pair.first, pair.second, perc);
    }
}

/**
 * \brief Метод для записи статистики high-load IP адресов
 * \author Jodode
 * \version 0.1
 * @param dstMap Словарь {IP : countOfAddress}
 * @param output Поток для записи результатов
 *
 * Внутри метода высчитывается распределение IP в процентах, а затем результат записывается в указанный пользователем
 * поток, существует автоматическое определение формата вывода (csv,txt). Выводимые данные можно фильтровать с помощью
 * конфиг файла
 */
void writeDstIPv4(std::map<uint32_t, uint32_t>& dstMap, std::ostream& output) {
    output << fmt::format((fileFormat == "csv" ? "{}\n{},{},{}\n" : "|{:=^48}|\n|{:^16}{:^16}{:^16}|\n"),
                          "Dest IPv4 stats", "IPv4", "count", "perc");
    size_t totalIPv4 = 0;
    for (auto& pair : dstMap)
        totalIPv4 += pair.second;

    for (auto& pair : dstMap) {
        double perc = getPerc(pair.second, totalIPv4);
        if (perc > minimalPercIP)
            output << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:<16}{:<16}{:<16.3}|\n"),
                                  pcpp::IPv4Address(pair.first).toString(), pair.second, perc);
    }
}

/**
 * \brief Метод для записи статистики
 * \author Jodode
 * \version 0.1
 * @param stats Хранилище статистики
 * @param output Поток для записи результатов
 *
 * Внутри метода вызывается вызов других метод для записи всей доступной статистики, а также дополнительно распределение
 * запросов между протоколами UDP и TCP.
 */
void writeResults(StatsCollector& stats, std::ostream& output) {
    output << fmt::format((fileFormat == "csv" ? "{}\n{},{},{}\n" : "|{:=^48}|\n|{:^16}{:^16}{:^16}|\n"),
                          "General packets info", "total", "collected", "dropped");
    output << fmt::format((fileFormat == "csv" ? "{},{},{}\n" : "|{:^16}{:^16}{:^16}|\n"),
                          stats.totalPackets, stats.totalPackets - stats.droppedPackets, stats.droppedPackets);
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
                          getPerc(stats.udpStats.numOfPackets, stats.udpStats.numOfPackets + stats.tcpStats.numOfPackets));
    output << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:^16}{:<16}{:<16.3}|\n"), "TCP",
                          stats.tcpStats.numOfPackets,
                          getPerc(stats.tcpStats.numOfPackets, stats.udpStats.numOfPackets + stats.tcpStats.numOfPackets));

}




int main(int argc, char* argv[]) {
    std::map<std::string, docopt::value> args
            = docopt::docopt(USAGE,
                             { argv + 1, argv + argc },
                             true,
                             VERSION);


    if (args.find("--test")->second) {

        std::srand((unsigned) time(nullptr));

        uint32_t dstPort = (std::rand() % (65535 - 1000)) + 1000;
        uint32_t dstIP = std::rand();
        size_t totalPorts = 1;
        size_t totalIP = 1;

        StatsCollector stats;
        size_t length;
        std::vector<size_t> udpPackets;
        size_t udpMax = 0;
        uint32_t max_UDP = std::rand() % 1000;
        for (uint32_t i = 0; i < max_UDP; ++i) {
            if (std::rand() % 13 == 0 && i != 0) {
                dstPort = (std::rand() % (65535 - 1000)) + 1000;
                ++totalPorts;
            }
            if (std::rand() % 13 == 0 && i != 0) {
                dstIP = std::rand();
                ++totalIP;
            }
            length = std::rand() % 1000;
            udpPackets.push_back(length);
            if (length > udpMax) udpMax = length;
            pcpp::EthLayer newEthernetLayer(pcpp::MacAddress("00:50:43:11:22:33"), pcpp::MacAddress("aa:bb:cc:dd:ee"));
            pcpp::IPv4Layer newIPLayer(pcpp::IPv4Address("192.168.1.1"),
                                       pcpp::IPv4Address(pcpp::IPv4Address(dstIP).toString()));
            newIPLayer.getIPv4Header()->ipId = pcpp::hostToNet16(2000);
            newIPLayer.getIPv4Header()->timeToLive = 64;
            pcpp::UdpLayer newUdpLayer(12345, dstPort);
            pcpp::DnsLayer newDnsLayer;
            newDnsLayer.addQuery("www.ebay.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
            pcpp::Packet UDPPacket(100);
            UDPPacket.addLayer(&newEthernetLayer);
            UDPPacket.addLayer(&newIPLayer);
            UDPPacket.addLayer(&newUdpLayer);
            UDPPacket.addLayer(&newDnsLayer);
            UDPPacket.computeCalculateFields();
            stats.collectPacket(UDPPacket);

        }

        std::vector<size_t> tcpPackets;
        size_t tcpMax = 0;
        uint32_t max_TCP = std::rand() % 1000;
        for (uint32_t i = 0; i < max_TCP; ++i) {
            if (std::rand() % 13 == 0 && i != 0) {
                dstPort = (std::rand() % (65535 - 1000)) + 1000;
                ++totalPorts;
            }
            if (std::rand() % 13 == 0 && i != 0) {
                dstIP = std::rand();
                ++totalIP;
            }
            length = std::rand() % 1000;
            tcpPackets.push_back(length);
            if (length > tcpMax) tcpMax = length;
            pcpp::EthLayer nEthernetLayer(pcpp::MacAddress("00:50:43:11:22:33"), pcpp::MacAddress("aa:bb:cc:dd:ee"));
            pcpp::IPv4Layer nIPLayer(pcpp::IPv4Address("192.168.1.1"),
                                     pcpp::IPv4Address(pcpp::IPv4Address(dstIP).toString()));
            nIPLayer.getIPv4Header()->ipId = pcpp::hostToNet16(2000);
            nIPLayer.getIPv4Header()->timeToLive = 64;
            pcpp::TcpLayer newTcpLayer(12345, dstPort);
            pcpp::DnsLayer nDnsLayer;
            nDnsLayer.addQuery("www.ebay.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
            pcpp::Packet TCPPacket(100);
            TCPPacket.addLayer(&nEthernetLayer);
            TCPPacket.addLayer(&nIPLayer);
            TCPPacket.addLayer(&newTcpLayer);
            TCPPacket.addLayer(&nDnsLayer);
            TCPPacket.computeCalculateFields();
            stats.collectPacket(TCPPacket);
        }

        auto assertExp = [](size_t value, size_t ans) -> bool {return value == ans;};
        require("Total packets",assertExp(stats.totalPackets, max_TCP + max_UDP));
        require("Collected packets",assertExp(stats.totalPackets - stats.droppedPackets, max_TCP + max_UDP));
        require("Dropped packets",assertExp(stats.droppedPackets, 0));
        require("Count UDP packets",assertExp(stats.udpStats.numOfPackets, max_UDP));
        require("Count TCP packets",assertExp(stats.tcpStats.numOfPackets, max_TCP));
        require("Count destination ports",assertExp(stats.dstPorts.size(), totalPorts));
        require("Count destination IP",assertExp(stats.dstIPv4.size(), totalIP));
        require("Percent calculating", getPerc(size_t(1), size_t(3)) - 33.333333333 > 0.0000000000001);

        std::cout << fmt::format((fileFormat == "csv" ? "{}\n{},{},{}\n" : "|{:=^48}|\n|{:^16}{:^16}{:^16}|\n"),
                              "General packets info", "total", "collected", "dropped");
        std::cout << fmt::format((fileFormat == "csv" ? "{},{},{}\n" : "|{:^16}{:^16}{:^16}|\n"),
                              stats.totalPackets, stats.totalPackets - stats.droppedPackets, stats.droppedPackets);
        if (stats.udpStats.numOfPackets > 0)
            writePayloadLen(udpMax, udpPackets,  "UDP", std::cout);
        if (stats.tcpStats.numOfPackets > 0)
            writePayloadLen(tcpMax, tcpPackets,  "TCP", std::cout);
        if (!stats.dstPorts.empty())
            writeDstPorts(stats.dstPorts, std::cout);
        if (!stats.dstIPv4.empty())
            writeDstIPv4(stats.dstIPv4, std::cout);
        std::cout << fmt::format((fileFormat == "csv" ? "{}\n{},{},{}\n" : "|{:=^48}|\n|{:^16}{:^16}{:^16}|\n"),
                              "Protocols distribution", "protocol", "count", "perc");
        std::cout << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:^16}{:<16}{:<16.3}|\n"), "UDP",
                              stats.udpStats.numOfPackets,
                              getPerc(stats.udpStats.numOfPackets, stats.udpStats.numOfPackets + stats.tcpStats.numOfPackets));
        std::cout << fmt::format((fileFormat == "csv" ? "{},{},{:.3}\n" : "|{:^16}{:<16}{:<16.3}|\n"), "TCP",
                              stats.tcpStats.numOfPackets,
                              getPerc(stats.tcpStats.numOfPackets, stats.udpStats.numOfPackets + stats.tcpStats.numOfPackets));

    }

    StatsCollector statsCollector;

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