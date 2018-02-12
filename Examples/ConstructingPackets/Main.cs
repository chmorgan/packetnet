using System;
using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet.Ethernet;
using PacketDotNet.IP;
using PacketDotNet.Tcp;

namespace ConstructingPackets
{
    /// <summary>
    ///     Example that shows how to construct a packet using packet constructors
    ///     to build a tcp/ip ipv4 packet
    /// </summary>
    internal class MainClass
    {
        public static void Main(String[] args)
        {
            UInt16 tcpSourcePort = 123;
            UInt16 tcpDestinationPort = 321;
            var tcpPacket = new TcpPacket(tcpSourcePort, tcpDestinationPort);

            var ipSourceAddress = IPAddress.Parse("192.168.1.1");
            var ipDestinationAddress = IPAddress.Parse("192.168.1.2");
            var ipPacket = new IPv4Packet(ipSourceAddress, ipDestinationAddress);

            var sourceHwAddress = "90-90-90-90-90-90";
            var ethernetSourceHwAddress = PhysicalAddress.Parse(sourceHwAddress);
            var destinationHwAddress = "80-80-80-80-80-80";
            var ethernetDestinationHwAddress = PhysicalAddress.Parse(destinationHwAddress);
            // NOTE: using EthernetPacketType.None to illustrate that the ethernet
            //       protocol type is updated based on the packet payload that is
            //       assigned to that particular ethernet packet
            var ethernetPacket = new EthernetPacket(ethernetSourceHwAddress,
                ethernetDestinationHwAddress,
                EthernetPacketType.None);

            // Now stitch all of the packets together
            ipPacket.PayloadPacket = tcpPacket;
            ethernetPacket.PayloadPacket = ipPacket;

            // and print out the packet to see that it looks just like we wanted it to
            Console.WriteLine(ethernetPacket.ToString());
        }
    }
}