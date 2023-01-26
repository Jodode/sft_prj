/**
 \file
 \brief Заголовочный файл с описанием классов

 Данный файл содержит в себе определения основных
 классов, используемых в программе
*/

#ifndef STATS_H
#define STATS_H

#include <map>
#include <sstream>
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "IPv4Layer.h"
#include "EthLayer.h"
#include "PayloadLayer.h"
#include "PacketUtils.h"
#include "SystemUtils.h"

/**
 * \brief Функция для вставки/изменения в словаре
 * \author Jodode
 * @param map Целевой словарь
 * @param val Ключ к словарю
 *
 *
 */
void upsert(std::map<uint32_t, uint32_t> &map, uint32_t val){
    if (map.find(val) == map.end())
        map[val] = 1;
    else
        ++map[val];
}
//! Базовая структура
/**
 * \brief Структура основной статистики для всех видов протоколов
 * \author Jodode
 * \version 0.1
 *
 * Данная структура является необходимым минимумом для хранения статистики протокола, родительский класс (скелет для других протоколов)
 */
struct GeneralStats {
    //! Функция очищения
    /**
     * Очищает значения всех переменных и объектов класса
     */
    void clear() {
        numOfPackets = 0;
        amountOfPackets = 0;
        sizeOfPackets = std::vector<size_t>();
    }

    //! Суммарное количество пакетов переданных с помощью протокола
    size_t numOfPackets{};
    //! Суммарный объем пакетов переданных с помощью протокола
    uint64_t amountOfPackets{};
    //! Вектор, с размерами "полезной нагрузки" каждого пакета
    std::vector<size_t> sizeOfPackets;
};
//! UDP структура
/**
 * \brief Структура статистики для UDP протокола
 * \author Jodode
 * \version 0.1
 *
 * Данная структура хранит в себе ключевую статистику о UDP пакетах
 */
struct UDPStats : GeneralStats {
    //! Максимальный размер "полезной нагрузки" переданной с помощью протокола UDP
    size_t udpMax = 0;

    /**
     * \brief Обработка слоя
     * \author Jodode
     * \version 0.1
     * @param udpLayer ссылка на UDP слой
     *
     * Функция обрабатывает информацию из UDP слоя и сохраняет её внутри объекта для дальнейшего анализа
     */
    void update(pcpp::UdpLayer* udpLayer) {
        size_t length = udpLayer->getLayerPayloadSize();

        ++numOfPackets;
        if (length > udpMax) udpMax = length;
        amountOfPackets += length;
        sizeOfPackets.push_back(length);
    }
};

//! TCP структура
/**
 * \brief Структура статистики для TCP протокола
 * \author Jodode
 * \version 0.1
 *
 * Данная структура хранит в себе ключевую статистику о TCP пакетах
 */
struct TCPStats : GeneralStats {
    //! Максимальный размер "полезной нагрузки" переданной с помощью протокола TCP
    size_t tcpMax = 0;

    /**
     * \brief Обработка слоя
     * \author Jodode
     * \version 0.1
     * @param tcpLayer ссылка на TCP слой
     *
     * Функция обрабатывает информацию из TCP слоя и сохраняет её внутри объекта для дальнейшего анализа
     */
    void update(pcpp::TcpLayer* tcpLayer) {
        size_t length = tcpLayer->getLayerPayloadSize();

        ++numOfPackets;
        if (length > tcpMax) tcpMax = length;
        amountOfPackets += length;
        sizeOfPackets.push_back(length);
    }
};

//! Хранилище статистики
/**
 * \brief Структура общей статистики
 * \author Jodode
 * \version 0.1
 *
 * Данная структура хранит в себе статистику о различных протоколах (UDP, TCP), а также суммарное число пакетов их трафика,
 * частоту обращений на разные IP адреса и разные порты
 *
 */
struct StatsCollector {
    //! Конструктор
    StatsCollector() { this->clear();}
    //! Деструктор
    ~StatsCollector() = default;

    //! UDP статистика
    UDPStats udpStats;
    //! TCP статистика
    TCPStats tcpStats;
    //! Общее число пакетов в траффике
    size_t totalPackets{};
    //! Число пакетов не относящихся к UDP/TCP
    size_t droppedPackets{};
    //! Частота обращений на порты
    std::map<uint32_t, uint32_t> dstPorts;
    //! Частота обращений на IP адреса
    std::map<uint32_t, uint32_t> dstIPv4;

    //! Функция очищения
    /**
     * Очищает значения всех переменных и объектов класса
     */
    void clear() {
        udpStats.clear();
        tcpStats.clear();
        totalPackets = 0;
        droppedPackets = 0;
        dstPorts = std::map<uint32_t, uint32_t>();
    }

    /**
     * \brief Функция "сбора" пакета в хранилище
     * \author Jodode
     * \version 0.1
     * @param packet пакет прошедший парсинг из "сырых" данных
     *
     * Обновляет значение переменных в хранилище, определяет тип пакета и отправляет на обработку, затем записывает
     * информацию об IP адресе и порте
     */
    void collectPacket (pcpp::Packet &packet) {
        ++totalPackets;
        uint32_t port(0);
        if (packet.isPacketOfType(pcpp::TCP)) {
            auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>();
            tcpStats.update(tcp);
            port = tcp->getDstPort();
        } else if (packet.isPacketOfType(pcpp::UDP)) {
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

#endif // STATS_H