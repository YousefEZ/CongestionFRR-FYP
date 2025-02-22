#ifndef LFA_POLICY_H
#define LFA_POLICY_H

#include <list>
#include <utility>

#include "ns3/queue.h"
#include "ns3/packet.h"
#include "point_to_point_frr_net_device.h"

namespace ns3
{

class LFAPolicy;

class LFAPolicy
{
  private:
    std::list<ns3::Ptr<ns3::PointToPointNetDevice>> m_alternateTargets;
    bool m_switch = false;

  public:
    LFAPolicy() = default;

    template <typename... DEVICES>
    void addAlternateTargets(DEVICES&&... devices);

    bool reroute(Ptr<Packet> packet, const Address& dest,
                 uint16_t protocolNumber);

    bool reroutable();

};

template <typename... DEVICES>
void LFAPolicy::addAlternateTargets(DEVICES&&... devices)
{
    (m_alternateTargets.push_back(std::forward<DEVICES>(devices)), ...);
}


bool LFAPolicy::reroutable()
{
  m_switch = !m_switch; 
  for (ns3::Ptr<ns3::PointToPointNetDevice> device : m_alternateTargets)
  {
    auto queue = device->GetQueue(); 
    return true; 
  }
  return false;
}

bool LFAPolicy::reroute(Ptr<Packet> packet, const Address& dest,
                        uint16_t protocolNumber)
{
    return !m_alternateTargets.empty() &&
           m_alternateTargets.front()->Send(packet, dest, protocolNumber);
}

} // namespace ns3

#endif
