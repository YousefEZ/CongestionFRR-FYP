#ifndef SAFE_REROUTE_TAIL_POLICY_H
#define SAFE_REROUTE_TAIL_POLICY_H

#include <list>
#include <utility>

#include "ns3/queue.h"
#include "ns3/packet.h"
#include "ns3/ppp-header.h"
#include "ns3/packet.h"
#include "point_to_point_frr_net_device.h"
#include "../libs/lfa_policy.h"

namespace ns3
{

struct SafeRerouteTailPolicy;

struct SafeRerouteTailPolicy : LFAPolicy {
    SafeRerouteTailPolicy() = default;
    virtual ~SafeRerouteTailPolicy() = default;

    bool isAlternateQueueCongested();

    virtual bool handlePacket(Ptr<Packet> newPacket, const Address& dest,
                              uint16_t protocolNumber,
                              PointToPointFRRNetDevice& device) override;
};

bool SafeRerouteTailPolicy::isAlternateQueueCongested()
{
    Ptr<Queue<Packet>> alternateQueue = m_alternate.GetQueue();
    return alternateQueue->GetNPackets() * 2 >=
           alternateQueue->GetMaxSize().GetValue();
}

bool SafeRerouteTailPolicy::handlePacket(Ptr<Packet> newPacket,
                                         const Address& dest,
                                         uint16_t protocolNumber,
                                         PointToPointFRRNetDevice& device)
{
    if (!device.isCongested() || isAlternateQueueCongested())
        return device.sendPacket(newPacket, dest, protocolNumber);

    return reroute(newPacket, dest, protocolNumber);
}

} // namespace ns3

#endif
