#include <iostream>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/log.h"
#include "ns3/traffic-control-module.h"
#include "ns3/packet.h"

#include "../libs/frr_queue.h"
#include "../libs/dummy_congestion_policy.h"
#include "../libs/modulo_congestion_policy.h"
#include "../libs/lfa_policy.h"
#include "../libs/random_congestion_policy.h"
#include "../libs/point_to_point_frr_helper.h"
#include "../libs/basic_congestion.h"
#include "../libs/random/random.hpp"

using namespace ns3;
using Random = effolkronium::random_static;
uint32_t seed = 1;
using CongestionPolicy = BasicCongestionPolicy;
// using CongestionPolicy = RandomCongestionPolicy<100>;
using FRRPolicy = LFAPolicy;

using SimulationQueue = FRRQueue<CongestionPolicy>;
using FRRNetDevice = PointToPointFRRNetDevice<FRRPolicy>;
using FRRChannel = PointToPointFRRChannel<FRRPolicy>;

NS_OBJECT_ENSURE_REGISTERED(SimulationQueue);
NS_OBJECT_ENSURE_REGISTERED(FRRChannel);
NS_OBJECT_ENSURE_REGISTERED(FRRNetDevice);

template <int INDEX, typename DEVICE_TYPE>
Ptr<DEVICE_TYPE> getDevice(const NetDeviceContainer& devices)
{
    return devices.Get(INDEX)->GetObject<DEVICE_TYPE>();
}

template <int INDEX>
Ptr<SimulationQueue> getQueue(const NetDeviceContainer& devices)
{
    return DynamicCast<SimulationQueue>(
        getDevice<INDEX, FRRNetDevice>(devices)->GetQueue());
}

template <int INDEX>
void setAlternateTarget(const NetDeviceContainer& devices,
                        Ptr<ns3::NetDevice> target)
{
    getDevice<INDEX, FRRNetDevice>(devices)->addAlternateTarget(target);
}

// TCP parameters
uint32_t segmentSize = 1024;
uint32_t MTU_bytes = segmentSize + 54;

// Topology parameters
std::string bandwidth_primary = "2KBps";
std::string bandwidth_access = "2.5KBps";
std::string bandwidth_udp_access = "5KBps";
std::string delay_bottleneck = "20ms";
std::string delay_access = "20ms";
std::string delay_alternate = "20ms";
std::string bandwidth_alternate = "1.5KBps";

std::string bandwidth_destination = "10Mbps";

void SetupTCPConfig()
{
    // TCP recovery algorithm
    Config::SetDefault(
        "ns3::TcpL4Protocol::RecoveryType",
        TypeIdValue(TypeId::LookupByName("ns3::TcpClassicRecovery")));
    // Congestion control algorithm
    Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                       StringValue("ns3::TcpLinuxReno"));
    Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(1073741824));
    Config::SetDefault("ns3::TcpSocket::RcvBufSize", UintegerValue(1073741824));
    // Initial congestion window
    Config::SetDefault("ns3::TcpSocket::InitialCwnd", UintegerValue(1));
    // Set delayed ack count
    Config::SetDefault("ns3::TcpSocket::DelAckTimeout", TimeValue(Time("1ms")));
    Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(1));
    // Set segment size of packet
    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1024));
    // Enable/disable SACKs (disabled)
    Config::SetDefault("ns3::TcpSocketBase::Sack", BooleanValue(false));
    Config::SetDefault("ns3::TcpSocketBase::MinRto", TimeValue(Seconds(1.0)));
}

// NS_LOG_COMPONENT_DEFINE("CongestionFastReRoute");
int main(int argc, char* argv[])
{
    Packet::EnablePrinting();
    int cong_threshold = 0;
    int number_of_tcp_senders = 1;
    std::string dir = "";
    CommandLine cmd;
    cmd.AddValue("bandwidth_primary", "Bandwidth primary", bandwidth_primary);
    cmd.AddValue("bandwidth_access", "Bandwidth Access", bandwidth_access);
    cmd.AddValue("bandwidth_udp_access", "Bandwidth UDP Access",
                 bandwidth_udp_access);
    cmd.AddValue("delay_primary", "Delay Bottleneck", delay_bottleneck);
    cmd.AddValue("delay_access", "Delay Access", delay_access);
    cmd.AddValue("delay_alternate", "Delay Alternate", delay_alternate);
    cmd.AddValue("bandwidth_alternate", "Bandwidth Alternate",
                 bandwidth_alternate);
    cmd.AddValue("tcp_senders", "Number of TCP Senders", number_of_tcp_senders);
    cmd.AddValue("policy_threshold", "Congestion policy threshold",
                 cong_threshold);
    cmd.AddValue("dir", "Traces directory", dir);
    cmd.AddValue("seed", "The random seed", seed);

    RngSeedManager::SetSeed(seed);
    Random::seed(seed);
    cmd.Parse(argc, argv);

    BasicCongestionPolicy::usage_percentage = cong_threshold;

    // LogComponentEnable("FRRQueue", LOG_LEVEL_ERROR);
    LogComponentEnableAll(LOG_LEVEL_ERROR);
    /*
     *  +----------+      +-----------+
     *  |Congestion|      |  Traffic  |
     *  |  Sender  |      |  Sender   |
     * 0+----+-----+     1+-----+-----+
     *       |                  |
     *       |   +----------+   |
     *       +---+  Router  +---+
     *           |    01    |
     *          2+----+-----+--------+
     *                |              |
     *                |        +-----+----+
     *                |        |  Router  |
     *                |        |    03    |
     *           +----+-----+ 4+----+-----+
     *           |  Router  |       |
     *           |    02    +-------+
     *          3+----+-----+
     *                |
     *                |
     *           +----+-----+
     *           | Receiver |
     *           |          |
     *          5+----------+
     */
    // Topology Setup
    NS_LOG_INFO("Creating Topology");
    NodeContainer nodes;
    NodeContainer tcp_devices;
    nodes.Create(5);
    tcp_devices.Create(number_of_tcp_senders);
    Names::Add("CongestionSender", nodes.Get(0));
    for (int i = 0; i < number_of_tcp_senders; i++)
        Names::Add("TrafficSender" + std::to_string(i), tcp_devices.Get(i));

    Names::Add("Router01", nodes.Get(1));
    Names::Add("Router02", nodes.Get(2));
    Names::Add("Router03", nodes.Get(3));
    Names::Add("Receiver", nodes.Get(4));

    InternetStackHelper stack;
    stack.Install(nodes);
    stack.Install(tcp_devices);

    // Configure PointToPoint link for normal traffic
    PointToPointHelper p2p_traffic;
    p2p_traffic.SetDeviceAttribute("DataRate", StringValue(bandwidth_access));
    p2p_traffic.SetChannelAttribute("Delay", StringValue(delay_access));
    // Set the custom queue for the device
    p2p_traffic.SetQueue("ns3::DropTailQueue<Packet>");
    // Install devices and channels between nodes

    PointToPointHelper p2p_destination;

    p2p_destination.SetDeviceAttribute("DataRate",
                                       StringValue(bandwidth_destination));
    p2p_destination.SetChannelAttribute("Delay", StringValue(delay_access));
    // Set the custom queue for the device
    p2p_destination.SetQueue("ns3::DropTailQueue<Packet>");

    PointToPointFRRHelper<FRRPolicy> p2p_congested_link;
    // PointToPointHelper p2p_congested_link;
    p2p_congested_link.SetDeviceAttribute("DataRate",
                                          StringValue(bandwidth_primary));
    p2p_congested_link.SetChannelAttribute("Delay",
                                           StringValue(delay_bottleneck));
    p2p_congested_link.SetQueue(SimulationQueue::getQueueString());
    // p2p_congested_link.SetQueue("ns3::DropTailQueue<Packet>");

    Config::SetDefault("ns3::DropTailQueue<Packet>::MaxSize",
                       StringValue("10p"));
    Config::SetDefault(SimulationQueue::getQueueString() + "::MaxSize",
                       StringValue("10p"));

    PointToPointHelper p2p_alternate;
    p2p_alternate.SetDeviceAttribute("DataRate",
                                     StringValue(bandwidth_alternate));
    p2p_alternate.SetChannelAttribute("Delay", StringValue(delay_alternate));
    p2p_alternate.SetQueue("ns3::DropTailQueue<Packet>");

    std::list<NetDeviceContainer> tcp_senders;

    for (int i = 0; i < number_of_tcp_senders; i++) {
        tcp_senders.push_back(
            p2p_traffic.Install(tcp_devices.Get(i), nodes.Get(1)));
    }

    NetDeviceContainer devices_2_3 =
        p2p_congested_link.Install(nodes.Get(1), nodes.Get(2));
    NetDeviceContainer devices_2_4 =
        p2p_alternate.Install(nodes.Get(1), nodes.Get(3));
    NetDeviceContainer devices_4_3 =
        p2p_alternate.Install(nodes.Get(3), nodes.Get(2));
    NetDeviceContainer devices_3_5 =
        p2p_destination.Install(nodes.Get(2), nodes.Get(4));

    // Configure PointToPoint link for congestion link
    PointToPointHelper p2p_congestion;
    p2p_congestion.SetDeviceAttribute("DataRate",
                                      StringValue(bandwidth_udp_access));
    p2p_congestion.SetChannelAttribute("Delay", StringValue(delay_access));
    // Set the custom queue for the device
    p2p_congestion.SetQueue("ns3::DropTailQueue<Packet>");
    // Install devices and channels between nodes
    NetDeviceContainer devices_0_2 =
        p2p_congestion.Install(nodes.Get(0), nodes.Get(1));

    // Assign IP addresses to subnets
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces_0_2 = address.Assign(devices_0_2);
    address.NewNetwork();

    for (auto& tcp_sender : tcp_senders) {
        address.Assign(tcp_sender);
        address.NewNetwork();
    }

    Ipv4InterfaceContainer interfaces_2_3 = address.Assign(devices_2_3);
    address.NewNetwork();

    Ipv4InterfaceContainer interfaces_2_4 = address.Assign(devices_2_4);
    address.NewNetwork();

    Ipv4InterfaceContainer interfaces_4_3 = address.Assign(devices_4_3);
    address.NewNetwork();

    Ipv4InterfaceContainer interfaces_3_5 = address.Assign(devices_3_5);
    address.NewNetwork();

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Receiver address
    Ipv4Address receiver_addr = interfaces_3_5.GetAddress(1);

    // UDP Congestion traffic setup
    uint16_t udp_port = 50001;
    OnOffHelper udp_source("ns3::UdpSocketFactory",
                           InetSocketAddress(receiver_addr, udp_port));
    udp_source.SetAttribute(
        "OnTime", StringValue("ns3::ConstantRandomVariable[Constant=0.5]"));
    udp_source.SetAttribute(
        "OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.5]"));
    udp_source.SetAttribute("DataRate",
                            DataRateValue(DataRate(bandwidth_udp_access)));
    udp_source.SetAttribute("PacketSize", UintegerValue(1024));

    ApplicationContainer udp_app = udp_source.Install(nodes.Get(0));
    udp_app.Start(Seconds(15.0));
    udp_app.Stop(Seconds(300.0));

    DataRate b_access(bandwidth_access);
    DataRate b_bottleneck(bandwidth_primary);
    Time d_access(delay_access);
    Time d_bottleneck(delay_bottleneck);
    Time d_serialization("1.9ms");

    // TCP Setup
    SetupTCPConfig();
    uint16_t tcp_port = 50002;
    std::list<ApplicationContainer> tcp_apps;
    for (int i = 0; i < number_of_tcp_senders; i++) {
        BulkSendHelper tcp_source("ns3::TcpSocketFactory",
                                  InetSocketAddress(receiver_addr, tcp_port));
        tcp_source.SetAttribute("MaxBytes",
                                UintegerValue(100000)); // 0 for unlimited data
        tcp_source.SetAttribute("SendSize",
                                UintegerValue(1024)); // Packet size in bytes

        p2p_traffic.EnablePcap(dir, tcp_devices.Get(i)->GetId(), 1);

        tcp_apps.push_back(tcp_source.Install(tcp_devices.Get(i)));
        tcp_apps.back().Start(Seconds(0.0));
        tcp_apps.back().Stop(Seconds(300.0));
    }

    // Packet sink setup (Receiver node)
    PacketSinkHelper sink("ns3::TcpSocketFactory",
                          InetSocketAddress(Ipv4Address::GetAny(), tcp_port));
    ApplicationContainer sink_app = sink.Install(nodes.Get(4));
    sink_app.Start(Seconds(0.0));
    sink_app.Stop(Seconds(300.0));

    PacketSinkHelper udp_sink(
        "ns3::UdpSocketFactory",
        InetSocketAddress(Ipv4Address::GetAny(), udp_port));
    ApplicationContainer udp_sink_app = udp_sink.Install(nodes.Get(4));
    udp_sink_app.Start(Seconds(0.0));
    udp_sink_app.Stop(Seconds(300.0));

    // LFA Alternate Path setup
    // Set up an alternate forwarding target, assuming you have an alternate
    // path configured
    setAlternateTarget<0>(
        devices_2_3, getDevice<0, ns3::PointToPointNetDevice>(devices_2_4));
    setAlternateTarget<1>(
        devices_2_3, getDevice<1, ns3::PointToPointNetDevice>(devices_4_3));

    // p2p_traffic.EnablePcap(dir, nodes.Get(4)->GetId(), 1);
    p2p_traffic.EnablePcapAll(dir);
    p2p_destination.EnablePcapAll(dir);
    p2p_congestion.EnablePcapAll(dir);
    p2p_congested_link.EnablePcapAll(dir);

    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
