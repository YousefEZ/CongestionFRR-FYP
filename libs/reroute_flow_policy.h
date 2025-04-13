#ifndef REROUTE_FLOW_POLICY_H
#define REROUTE_FLOW_POLICY_H

#include <list>
#include <utility>
#include <algorithm>
#include <vector>
#include <unordered_set>
#include <iostream>

#include "ns3/queue.h"
#include "ns3/packet.h"
#include "point_to_point_frr_net_device.h"
#include "../libs/lfa_policy.h"

namespace ns3
{

class ReroutePerFlowPolicy;

using FourTuple = std::tuple<uint32_t, uint32_t, uint32_t, uint32_t>;

using HashedFourTuple = unsigned long long;

unsigned long long shift_left(unsigned long long value, unsigned int shift)
{
    return value << shift;
}

HashedFourTuple hashFourTuple(FourTuple flow)
{
    // return shift_left(std::get<0>(flow), 96) | shift_left(std::get<1>(flow),
    // 64) | shift_left(std::get<2>(flow), 32) | (std::get<3>(flow));
    return std::get<0>(flow);
}

HashedFourTuple Extract4Tuple(Ptr<const Packet> packet)
{
    Ptr<Packet> copy = packet->Copy();

    // Parse IP header
    Ipv4Header ipHeader;
    copy->PeekHeader(ipHeader);
    copy->RemoveHeader(ipHeader);

    Ipv4Address srcIp = ipHeader.GetSource();
    Ipv4Address dstIp = ipHeader.GetDestination();
    uint8_t protocol = ipHeader.GetProtocol();

    uint16_t srcPort = 0;
    uint16_t dstPort = 0;

    if (protocol == 6) // TCP
    {
        TcpHeader tcpHeader;
        copy->PeekHeader(tcpHeader);
        copy->RemoveHeader(tcpHeader);
        srcPort = tcpHeader.GetSourcePort();
        dstPort = tcpHeader.GetDestinationPort();
    } else if (protocol == 17) // UDP
    {
        UdpHeader udpHeader;
        copy->PeekHeader(udpHeader);
        copy->RemoveHeader(udpHeader);
        srcPort = udpHeader.GetSourcePort();
        dstPort = udpHeader.GetDestinationPort();
    } else {
        std::cout << "Unsupported transport protocol: " << (uint16_t)protocol
                  << std::endl;
        throw std::runtime_error("Unsupported transport protocol");
    }

    return hashFourTuple(
        std::make_tuple(srcIp.Get(), srcPort, dstIp.Get(), dstPort));
}

class ReroutePerFlowPolicy : public LFAPolicy
{
  private:
    std::unordered_map<HashedFourTuple, unsigned int> m_packet_count;
    std::unordered_set<HashedFourTuple> m_rerouted_flows;

    int get_number_active_flows();
    void reroute_highest_flow();

  public:
    ReroutePerFlowPolicy() = default;
    virtual ~ReroutePerFlowPolicy() = default;

    void register_packet(Ptr<Packet> packet);
    bool rerouted_flow(Ptr<Packet> packet);

    virtual bool handlePacket(Ptr<Packet> newPacket, const Address& dest,
                              uint16_t protocolNumber,
                              PointToPointFRRNetDevice& device) override;
};

void ReroutePerFlowPolicy::register_packet(Ptr<Packet> packet)
{
    HashedFourTuple flow = Extract4Tuple(packet);
    if (m_packet_count.contains(flow))
        m_packet_count[flow]++;
    else
        m_packet_count[flow] = 1;
}

bool ReroutePerFlowPolicy::rerouted_flow(Ptr<Packet> packet)
{
    return m_rerouted_flows.contains(Extract4Tuple(packet));
}

int ReroutePerFlowPolicy::get_number_active_flows()
{
    return m_rerouted_flows.size();
}

void ReroutePerFlowPolicy::reroute_highest_flow()
{
    std::vector<std::pair<HashedFourTuple, unsigned int>> flows(
        m_packet_count.begin(), m_packet_count.end());

    std::sort(flows.begin(), flows.end(),
              [](auto& a, auto& b) { return a.second > b.second; });

    int remaining_counter = 1 - get_number_active_flows();

    for (auto& [flow, _] : flows) {
        if (remaining_counter == 0) return;
        if (m_rerouted_flows.contains(flow)) continue;

        m_rerouted_flows.insert(flow);
        remaining_counter--;
    }
}

bool ReroutePerFlowPolicy::handlePacket(Ptr<Packet> newPacket,
                                        const Address& dest,
                                        uint16_t protocolNumber,
                                        PointToPointFRRNetDevice& device)
{
    register_packet(newPacket);

    if (device.isCongested() && get_number_active_flows() < 1)
        reroute_highest_flow();

    if (rerouted_flow(newPacket))
        return reroute(newPacket, dest, protocolNumber);

    return device.sendPacket(newPacket, dest, protocolNumber);
}

} // namespace ns3
#endif
