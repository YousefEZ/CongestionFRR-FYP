#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <sys/stat.h>

#include "ns3/random-variable-stream.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/log.h"
#include "ns3/traffic-control-module.h"
#include "ns3/packet.h"
#include "ns3/tcp-linux-reno.h"

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

// Topology parameters
std::string bandwidth_primary = "3Mbps";
std::string bandwidth_tcp = "3Mbps";
std::string bandwidth_udp = "3Mbps";
std::string bandwidth_alternate = "2Mbps";
std::string bandwidth_destination = "1000Mbps";

std::string delay_primary = "2ms";
std::string delay_tcp = "2ms";
std::string delay_udp = "2ms";
std::string delay_alternate = "1ms";
std::string delay_destination = "2ms";

uint32_t tcpSegmentSize = 1446;
int number_of_tcp_senders = 1;
int tcp_bytes = 1000000;
float tcp_start = 0.0;
float tcp_end = 15.0;

bool enable_udp = false;
uint32_t udpSegmentSize = 1250;
float udp_start = 0.175;
float udp_end = 15.0;

std::string dir = "";

std::string traffic_queue_size = "4p";
std::string default_queue_size = "4p";

bool enable_rerouting = false;
bool enable_router_pcap = false;
bool enable_udp_pcap = false;
bool enable_logging = false;

float udp_on_time_mean = 0.5;
float udp_on_time_variance = 0.1;
float udp_on_time_bound = 0.25;

float udp_off_time_mean = 0.3;
float udp_off_time_variance = 0.1;
float udp_off_time_bound = 0.1;

uint32_t seed = 23643;
int run = 1;

int cong_threshold = 0;

using CongestionPolicy = BasicCongestionPolicy;
// using CongestionPolicy = RandomCongestionPolicy<100>;
using FRRPolicy = LFAPolicy;

using SimulationQueue = FRRQueue<CongestionPolicy>;
using FRRNetDevice = PointToPointFRRNetDevice<FRRPolicy>;
using FRRChannel = PointToPointFRRChannel<FRRPolicy>;

std::ofstream fPlotCwnd;

std::unordered_map<std::string, std::ofstream> fQueues;

void toggleCongestion(Ptr<SimulationQueue> queue)
{
    ;
    // queue->m_congestionPolicy.turnOff();
}

// void enableRerouting(Ptr<SimulationQueue> queue)
// {
//     // queue->m_congestionPolicy.enable();
// }

NS_OBJECT_ENSURE_REGISTERED(SimulationQueue);
NS_OBJECT_ENSURE_REGISTERED(FRRChannel);
NS_OBJECT_ENSURE_REGISTERED(FRRNetDevice);

void RtoExpiredCallback(SequenceNumber32 seq)
{
    std::cout << "RTO expired for packet sequence: " << seq << std::endl;
}

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
                        Ptr<ns3::PointToPointNetDevice> target)
{
    getDevice<INDEX, FRRNetDevice>(devices)->addAlternateTarget(target);
}

// Function to trace change in cwnd at n0
static void CwndChange(uint32_t oldCwnd, uint32_t newCwnd)
{
    fPlotCwnd << Simulator::Now().GetSeconds() << " "
              << newCwnd / tcpSegmentSize << std::endl;
}

// Function to trace change in cwnd at n0
static void RTOChange(Time oldRTO, Time newRTO)
{
    fPlotCwnd << Simulator::Now().GetSeconds()
              << " Old RTO=" << oldRTO.As(Time::S)
              << ", newRTO=" << newRTO.As(Time::S) << std::endl;
}

static void PacketInQueueChange(std::string queue, uint32_t oldPacketCount,
                                uint32_t newPacketCount)
{
    std::ofstream& fQueue = fQueues[queue];
    fQueue << Simulator::Now().GetSeconds() << " " << newPacketCount
           << std::endl;
}

static void EnqueuePacket(std::string queue, Ptr<const Packet> packet)
{
    std::ofstream& fQueue = fQueues[queue];
    fQueue << Simulator::Now().GetSeconds() << " ";
    packet->Print(fQueue);
    fQueue << std::endl;
}

// Trace Function for cwnd
void TraceCwnd(uint32_t node, uint32_t cwndWindow,
               Callback<void, uint32_t, uint32_t> CwndTrace)
{
    Config::ConnectWithoutContext("/NodeList/" + std::to_string(node) +
                                      "/$ns3::TcpL4Protocol/SocketList/" +
                                      std::to_string(cwndWindow) +
                                      "/CongestionWindow",
                                  CwndTrace);
}

void TraceRTO(uint32_t node, uint32_t cwndWindow,
              Callback<void, Time, Time> RTOTrace)
{
    Config::ConnectWithoutContext("/NodeList/" + std::to_string(node) +
                                      "/$ns3::TcpL4Protocol/SocketList/" +
                                      std::to_string(cwndWindow) + "/RTO",
                                  RTOTrace);
}

void SetupTCPConfig()
{
    Config::SetDefault(
        "ns3::TcpL4Protocol::RecoveryType",
        TypeIdValue(TypeId::LookupByName("ns3::TcpClassicRecovery")));
    Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                       StringValue("ns3::TcpLinuxReno"));
    Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(1073741824));
    Config::SetDefault("ns3::TcpSocket::RcvBufSize", UintegerValue(1073741824));
    Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(1));
    Config::SetDefault("ns3::TcpSocket::SegmentSize",
                       UintegerValue(tcpSegmentSize));
    Config::SetDefault("ns3::TcpSocketBase::Sack", BooleanValue(true));
}

// NS_LOG_COMPONENT_DEFINE("CongestionFastReRoute");
int main(int argc, char* argv[])
{
    Packet::EnablePrinting();

    CommandLine cmd;
    cmd.AddValue("bandwidth_primary", "Bandwidth primary", bandwidth_primary);
    cmd.AddValue("bandwidth_tcp", "Bandwidth Access", bandwidth_tcp);
    cmd.AddValue("bandwidth_udp", "Bandwidth UDP Access", bandwidth_udp);
    cmd.AddValue("bandwidth_alternate", "Bandwidth Alternate",
                 bandwidth_alternate);
    cmd.AddValue("bandwidth_destination", "Bandwidth Destination",
                 bandwidth_destination);

    cmd.AddValue("delay_primary", "Delay Bottleneck", delay_primary);
    cmd.AddValue("delay_tcp", "Delay TCP Access", delay_tcp);
    cmd.AddValue("delay_udp", "Delay UDP Access", delay_udp);
    cmd.AddValue("delay_alternate", "Delay Alternate", delay_alternate);
    cmd.AddValue("delay_destination", "Delay Destination", delay_destination);

    cmd.AddValue("tcp_segment_size", "TCP Segment Size", tcpSegmentSize);
    cmd.AddValue("tcp_senders", "Number of TCP Senders", number_of_tcp_senders);
    cmd.AddValue("tcp_bytes", "Amount of TCP bytes", tcp_bytes);
    cmd.AddValue("tcp_start_time", "When TCP starts", tcp_start);
    cmd.AddValue("tcp_end_time", "When TCP ends", tcp_end);

    cmd.AddValue("enable-udp", "enable udp traffic to be sent", enable_udp);
    cmd.AddValue("udp_start_time", "UDP start time", udp_start);
    cmd.AddValue("udp_segment_size", "UDP segment size", udpSegmentSize);
    cmd.AddValue("udp_end_time", "UDP End", udp_end);

    cmd.AddValue("udp_on_time_mean", "UDP On Time Mean", udp_on_time_mean);
    cmd.AddValue("udp_on_time_variance", "UDP On Time Variance",
                 udp_on_time_variance);
    cmd.AddValue("udp_on_time_bound", "UDP On Time Bound", udp_on_time_bound);

    cmd.AddValue("udp_off_time_mean", "UDP Off Time Mean", udp_off_time_mean);
    cmd.AddValue("udp_off_time_variance", "UDP Off Time Variance",
                 udp_off_time_variance);
    cmd.AddValue("udp_off_time_bound", "UDP Off Time Bound",
                 udp_off_time_bound);

    cmd.AddValue("policy_threshold", "Congestion policy threshold",
                 cong_threshold);
    cmd.AddValue("dir", "Traces directory", dir);
    cmd.AddValue("seed", "The random seed", seed);

    cmd.AddValue("traffic_queue_size", "Traffic queue size",
                 traffic_queue_size);
    cmd.AddValue("default_queue_size", "Default queue size",
                 default_queue_size);

    cmd.AddValue("enable-rerouting", "enable fast rerouting on congestion",
                 enable_rerouting);
    cmd.AddValue("enable-router-pcap", "enable pcap on routers",
                 enable_router_pcap);
    cmd.AddValue("enable-udp-pcap", "enable pcap on udp traffic",
                 enable_udp_pcap);
    cmd.AddValue("enable-logging", "enable logging", enable_logging);
    cmd.AddValue("run", "run number", run);

    cmd.Parse(argc, argv);

    RngSeedManager::SetSeed(seed);
    RngSeedManager::SetRun(run); // Set the run number (changes the stream)
    // Random::seed(seed);

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
    nodes.Create(6);
    tcp_devices.Create(number_of_tcp_senders);
    Names::Add("CongestionSender", nodes.Get(0));
    for (int i = 0; i < number_of_tcp_senders; i++)
        Names::Add("TrafficSender" + std::to_string(i), tcp_devices.Get(i));
    if (enable_logging) {
        ns3::LogComponentEnable("TcpLinuxReno", ns3::LOG_LEVEL_ALL);
        ns3::LogComponentEnable("TcpLinuxReno", ns3::LOG_PREFIX_TIME);
        ns3::LogComponentEnable("TcpSocketBase", ns3::LOG_LEVEL_DEBUG);
        ns3::LogComponentEnable("TcpSocketBase", ns3::LOG_PREFIX_TIME);
        ns3::LogComponentEnable("TcpL4Protocol", ns3::LOG_LEVEL_DEBUG);
        ns3::LogComponentEnable("TcpL4Protocol", ns3::LOG_PREFIX_TIME);
        ns3::LogComponentEnable("TcpTxBuffer", ns3::LOG_LEVEL_DEBUG);
        ns3::LogComponentEnable("TcpTxBuffer", ns3::LOG_PREFIX_TIME);
    }
    Names::Add("Router01", nodes.Get(1));
    Names::Add("Router02", nodes.Get(2));
    Names::Add("Router03", nodes.Get(3));
    Names::Add("Receiver", nodes.Get(4));
    Names::Add("Middle", nodes.Get(5));
    InternetStackHelper stack;
    stack.Install(nodes);
    stack.Install(tcp_devices);

    // Configure PointToPoint link for normal traffic
    PointToPointHelper p2p_traffic;
    p2p_traffic.SetDeviceAttribute("DataRate", StringValue(bandwidth_tcp));
    p2p_traffic.SetChannelAttribute("Delay", StringValue(delay_tcp));
    // Set the custom queue for the device
    p2p_traffic.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize",
                         StringValue(traffic_queue_size));
    // Install devices and channels between nodes

    PointToPointHelper p2p_destination;

    p2p_destination.SetDeviceAttribute("DataRate",
                                       StringValue(bandwidth_destination));
    p2p_destination.SetChannelAttribute("Delay",
                                        StringValue(delay_destination));
    // Set the custom queue for the device
    p2p_destination.SetQueue("ns3::DropTailQueue<Packet>");

    Config::SetDefault("ns3::DropTailQueue<Packet>::MaxSize",
                       StringValue(default_queue_size));
    Config::SetDefault(SimulationQueue::getQueueString() + "::MaxSize",
                       StringValue(default_queue_size));

    PointToPointHelper p2p_alternate;
    p2p_alternate.SetDeviceAttribute("DataRate",
                                     StringValue(bandwidth_alternate));
    p2p_alternate.SetChannelAttribute("Delay", StringValue(delay_alternate));
    p2p_alternate.SetQueue("ns3::DropTailQueue<Packet>");

    std::list<NetDeviceContainer> tcp_senders;

    for (int i = 0; i < number_of_tcp_senders; i++) {
        tcp_senders.push_back(
            p2p_destination.Install(tcp_devices.Get(i), nodes.Get(5)));
    }

    NetDeviceContainer devices_2_3;
    std::shared_ptr<PointToPointFRRHelper<FRRPolicy>> p2p_congested_link;
    std::shared_ptr<PointToPointHelper> p2p_congested_link_no_frr;

    fQueues["CongestedQueue"];
    fQueues["MiddleQueue"];
    fQueues["AlternateQueue"];
    if (enable_rerouting) {
        p2p_congested_link =
            std::make_shared<PointToPointFRRHelper<FRRPolicy>>();
        // PointToPointHelper p2p_congested_link;
        p2p_congested_link->SetDeviceAttribute("DataRate",
                                               StringValue(bandwidth_primary));
        p2p_congested_link->SetChannelAttribute("Delay",
                                                StringValue(delay_primary));
        p2p_congested_link->SetQueue(SimulationQueue::getQueueString());
        // p2p_congested_link.SetQueue("ns3::DropTailQueue<Packet>");

        devices_2_3 = p2p_congested_link->Install(nodes.Get(1), nodes.Get(2));
        auto queue = getQueue<0>(devices_2_3);
        queue->TraceConnectWithoutContext(
            "PacketsInQueue",
            MakeBoundCallback(&PacketInQueueChange, "CongestedQueue"));
        queue->TraceConnectWithoutContext(
            "Enqueue", MakeBoundCallback(&EnqueuePacket, "CongestedQueue"));
        if (enable_router_pcap) {
            p2p_congested_link->EnablePcap(
                dir, getDevice<0, ns3::PointToPointNetDevice>(devices_2_3));
        }
    } else {
        p2p_congested_link_no_frr = std::make_shared<PointToPointHelper>();
        p2p_congested_link_no_frr->SetDeviceAttribute(
            "DataRate", StringValue(bandwidth_primary));
        p2p_congested_link_no_frr->SetChannelAttribute(
            "Delay", StringValue(delay_primary));
        // p2p_congested_link_no_frr.SetQueue(SimulationQueue::getQueueString());
        p2p_congested_link_no_frr->SetQueue("ns3::DropTailQueue<Packet>");

        devices_2_3 =
            p2p_congested_link_no_frr->Install(nodes.Get(1), nodes.Get(2));

        auto queue =
            getDevice<0, PointToPointNetDevice>(devices_2_3)->GetQueue();
        queue->TraceConnectWithoutContext(
            "PacketsInQueue",
            MakeBoundCallback(&PacketInQueueChange, "CongestedQueue"));
        queue->TraceConnectWithoutContext(
            "Enqueue", MakeBoundCallback(&EnqueuePacket, "CongestedQueue"));
        if (enable_router_pcap) {
            p2p_congested_link_no_frr->EnablePcap(
                dir, getDevice<0, ns3::PointToPointNetDevice>(devices_2_3));
        }
    }

    NetDeviceContainer devices_2_4 =
        p2p_alternate.Install(nodes.Get(1), nodes.Get(3));
    NetDeviceContainer devices_4_3 =
        p2p_alternate.Install(nodes.Get(3), nodes.Get(2));
    NetDeviceContainer devices_3_5 =
        p2p_destination.Install(nodes.Get(2), nodes.Get(4));

    NetDeviceContainer devices_M_2 =
        p2p_traffic.Install(nodes.Get(5), nodes.Get(1));

    auto middleQueue =
        getDevice<0, PointToPointNetDevice>(devices_M_2)->GetQueue();
    middleQueue->TraceConnectWithoutContext(
        "PacketsInQueue",
        MakeBoundCallback(&PacketInQueueChange, "MiddleQueue"));
    middleQueue->TraceConnectWithoutContext(
        "Enqueue", MakeBoundCallback(&EnqueuePacket, "MiddleQueue"));

    auto queue = getDevice<0, PointToPointNetDevice>(devices_2_4)->GetQueue();
    queue->TraceConnectWithoutContext(
        "PacketsInQueue",
        MakeBoundCallback(&PacketInQueueChange, "AlternateQueue"));
    queue->TraceConnectWithoutContext(
        "Enqueue", MakeBoundCallback(&EnqueuePacket, "AlternateQueue"));

    // Configure PointToPoint link for congestion link
    PointToPointHelper p2p_congestion;
    p2p_congestion.SetDeviceAttribute("DataRate", StringValue(bandwidth_udp));
    p2p_congestion.SetChannelAttribute("Delay", StringValue(delay_udp));
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

    Ipv4InterfaceContainer interfaces_M_2 = address.Assign(devices_M_2);
    address.NewNetwork();

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
    std::shared_ptr<OnOffHelper> udp_source;
    std::shared_ptr<ApplicationContainer> udp_app;
    if (enable_udp) {
        udp_source = std::make_shared<OnOffHelper>(
            "ns3::UdpSocketFactory",
            InetSocketAddress(receiver_addr, udp_port));
        Ptr<NormalRandomVariable> on_time =
            CreateObject<NormalRandomVariable>();
        on_time->SetAttribute("Mean", DoubleValue(udp_on_time_mean));
        on_time->SetAttribute("Variance", DoubleValue(udp_on_time_variance));
        on_time->SetAttribute("Bound", DoubleValue(udp_on_time_bound));
        Ptr<NormalRandomVariable> off_time =
            CreateObject<NormalRandomVariable>();
        off_time->SetAttribute("Mean", DoubleValue(udp_off_time_mean));
        off_time->SetAttribute("Variance", DoubleValue(udp_off_time_variance));
        off_time->SetAttribute("Bound", DoubleValue(udp_off_time_bound));

        udp_source->SetAttribute("OnTime", PointerValue(on_time));
        udp_source->SetAttribute("OffTime", PointerValue(off_time));

        udp_source->SetAttribute("DataRate",
                                 DataRateValue(DataRate(bandwidth_udp)));
        // udp_source->SetAttribute("PacketSize", UintegerValue(1470));
        udp_source->SetAttribute("PacketSize", UintegerValue(udpSegmentSize));

        udp_app = std::make_shared<ApplicationContainer>(
            udp_source->Install(nodes.Get(0)));
        udp_app->Start(Seconds(udp_start));
        udp_app->Stop(Seconds(udp_end));
    }
    DataRate b_access(bandwidth_tcp);
    DataRate b_bottleneck(bandwidth_primary);
    Time d_access(delay_tcp);
    Time d_bottleneck(delay_primary);
    Time d_serialization("1.9ms");

    // TCP Setup
    SetupTCPConfig();
    uint16_t tcp_port = 50002;
    std::list<ApplicationContainer> tcp_apps;
    for (int i = 0; i < number_of_tcp_senders; i++) {
        BulkSendHelper tcp_source("ns3::TcpSocketFactory",
                                  InetSocketAddress(receiver_addr, tcp_port));
        tcp_source.SetAttribute(
            "MaxBytes",
            UintegerValue(tcp_bytes)); // 0 for unlimited data

        Simulator::Schedule(Seconds(0.001), &TraceCwnd,
                            tcp_devices.Get(i)->GetId(), 0,
                            MakeCallback(&CwndChange));
        Simulator::Schedule(Seconds(0.01), &TraceRTO,
                            tcp_devices.Get(i)->GetId(), 0,
                            MakeCallback(&RTOChange));

        tcp_apps.push_back(tcp_source.Install(tcp_devices.Get(i)));
        tcp_apps.back().Start(Seconds(tcp_start));
        tcp_apps.back().Stop(Seconds(tcp_end));
    }

    // Simulator::Schedule(Seconds(0.001), &TraceCwnd,
    // tcp_devices.Get(i)->GetId(), 0, MakeCallback(&CwndChange)); Packet sink
    // setup (Receiver node)
    PacketSinkHelper sink("ns3::TcpSocketFactory",
                          InetSocketAddress(Ipv4Address::GetAny(), tcp_port));
    ApplicationContainer sink_app = sink.Install(nodes.Get(4));
    sink_app.Start(Seconds(0.0));
    sink_app.Stop(Seconds(tcp_end));

    PacketSinkHelper udp_sink(
        "ns3::UdpSocketFactory",
        InetSocketAddress(Ipv4Address::GetAny(), udp_port));
    ApplicationContainer udp_sink_app = udp_sink.Install(nodes.Get(4));
    udp_sink_app.Start(Seconds(0.0));
    udp_sink_app.Stop(Seconds(udp_end));

    // LFA Alternate Path setup
    // Set up an alternate forwarding target, assuming you have an alternate
    // path configured
    if (enable_rerouting) {
        setAlternateTarget<0>(
            devices_2_3, getDevice<0, ns3::PointToPointNetDevice>(devices_2_4));
        setAlternateTarget<1>(
            devices_2_3, getDevice<1, ns3::PointToPointNetDevice>(devices_4_3));
    }

    // p2p_traffic.EnablePcap(dir, nodes.Get(4)->GetId(), 1);
    if (enable_router_pcap) {
        p2p_traffic.EnablePcap(dir, getDevice<0, ns3::PointToPointNetDevice>(
                                        devices_M_2)); // Middle Router
        p2p_alternate.EnablePcap(dir, getDevice<0, ns3::PointToPointNetDevice>(
                                          devices_2_4)); // Router1 --> Router2
        p2p_alternate.EnablePcap(dir, getDevice<0, ns3::PointToPointNetDevice>(
                                          devices_4_3)); // Router2 --> Router3
        p2p_destination.EnablePcap(dir,
                                   getDevice<0, ns3::PointToPointNetDevice>(
                                       devices_3_5)); // Router3 --> Receiver
    }
    if (enable_udp_pcap) {
        p2p_congestion.EnablePcap(
            dir, getDevice<0, ns3::PointToPointNetDevice>(devices_0_2));
    }

    for (auto& sender_container : tcp_senders)
        p2p_destination.EnablePcap(
            dir, getDevice<0, ns3::PointToPointNetDevice>(sender_container));
    p2p_destination.EnablePcap(
        dir, getDevice<1, ns3::PointToPointNetDevice>(devices_3_5));
    fPlotCwnd.open(dir + "n0.dat", std::ios::out);
    for (auto& [queueName, q] : fQueues) {
        q.open(dir + queueName + ".dat", std::ios::out);
    }
    Simulator::Run();
    Simulator::Destroy();

    fPlotCwnd.close();
    for (auto& [queueName, q] : fQueues) {
        q.close();
    }
    return 0;
}
