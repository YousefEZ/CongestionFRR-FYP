#ifndef LFA_POLICY_H
#define LFA_POLICY_H

#include <list>
#include <utility>

#include "ns3/queue.h"
#include "ns3/packet.h"
#include "ns3/point-to-point-net-device.h"

namespace ns3
{

class PointToPointFRRNetDevice;

class ReroutingPolicy
{
  public:
    virtual ~ReroutingPolicy() = default;

    virtual bool reroute(Ptr<Packet> packet, const Address& dest,
                         uint16_t protocolNumber) = 0;

    virtual void addAlternateTarget(Ptr<PointToPointNetDevice> device) = 0;

    virtual bool handlePacket(Ptr<Packet> newPacket, const Address& dest,
                              uint16_t protocolNumber,
                              PointToPointFRRNetDevice& device) = 0;
};

class LFAPolicy : public ReroutingPolicy
{
  protected:
    Ptr<PointToPointNetDevice> m_alternate;

  public:
    virtual ~LFAPolicy() = default;

    virtual bool reroute(Ptr<Packet> packet, const Address& dest,
                         uint16_t protocolNumber) override;

    virtual void addAlternateTarget(Ptr<PointToPointNetDevice> device) override;

    virtual bool handlePacket(Ptr<Packet> newPacket, const Address& dest,
                              uint16_t protocolNumber,
                              PointToPointFRRNetDevice& device) = 0;
};

void LFAPolicy::addAlternateTarget(Ptr<PointToPointNetDevice> device)
{
    m_alternate = device;
}

bool LFAPolicy::reroute(Ptr<Packet> packet, const Address& dest,
                        uint16_t protocolNumber)
{
    std::stringstream packetStream;
    packet->Print(packetStream);
    return !!m_alternate && m_alternate->Send(packet, dest, protocolNumber);
}

} // namespace ns3
#endif
