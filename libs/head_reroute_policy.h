#ifndef REROUTE_HEAD_POLICY_H
#define REROUTE_HEAD_POLICY_H

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

struct RerouteHeadPolicy;

struct RerouteHeadPolicy : public LFAPolicy {
    RerouteHeadPolicy() = default;
    virtual ~RerouteHeadPolicy() = default;
    virtual bool handlePacket(Ptr<Packet> newPacket, const Address& dest,
                              uint16_t protocolNumber,
                              PointToPointFRRNetDevice& device) override;
};

bool RerouteHeadPolicy::handlePacket(Ptr<Packet> newPacket, const Address& dest,
                                     uint16_t protocolNumber,
                                     PointToPointFRRNetDevice& device)
{
    if (!device.isCongested()) {
        return device.sendPacket(newPacket, dest, protocolNumber);
    }

    Ptr<Packet> head = device.GetQueue()->Dequeue();
    device.sendPacket(newPacket, dest, protocolNumber);

    PppHeader ppp;
    ppp.SetProtocol(device.EtherToPpp(protocolNumber));
    head->RemoveHeader(ppp);

    return reroute(head, dest, protocolNumber);
}

} // namespace ns3
#endif
