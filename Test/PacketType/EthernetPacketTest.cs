/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/
/*
 * Copyright 2008-2009 Chris Morgan <chmorgan@gmail.com>
 */

using System;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.Serialization.Formatters.Binary;
using NUnit.Framework;
using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType
{
    [TestFixture]
    public class EthernetPacketTest
    {
        // tcp
        public void VerifyPacket0(Packet p, RawCapture rawCapture)
        {
            Console.WriteLine(p.ToString());

            var e = (EthernetPacket) p;
            Assert.AreEqual(PhysicalAddress.Parse("00-13-10-03-71-47"), e.SourceHardwareAddress);
            Assert.AreEqual(PhysicalAddress.Parse("00-E0-4C-E5-73-AD"), e.DestinationHardwareAddress);

            var ip = (IPPacket) e.PayloadPacket;
            Assert.AreEqual(System.Net.IPAddress.Parse("82.165.240.134"), ip.SourceAddress);
            Assert.AreEqual(System.Net.IPAddress.Parse("192.168.1.221"), ip.DestinationAddress);
            Assert.AreEqual(IPVersion.IPv4, ip.Version);
            Assert.AreEqual(ProtocolType.Tcp, ip.Protocol);
            Assert.AreEqual(254, ip.TimeToLive);
            Assert.AreEqual(0x0df8, ((IPv4Packet) ip).CalculateIPChecksum());
            Assert.AreEqual(1176685346, rawCapture.Timeval.Seconds);
            Assert.AreEqual(885259.000, rawCapture.Timeval.MicroSeconds);

            var tcp = (TcpPacket) ip.PayloadPacket;
            Assert.AreEqual(80, tcp.SourcePort);
            Assert.AreEqual(4324, tcp.DestinationPort);
            Assert.IsTrue(tcp.Acknowledgment);
            Assert.AreEqual(3536, tcp.WindowSize);
            Assert.AreEqual(0xc835, tcp.CalculateTcpChecksum());
            Console.WriteLine("tcp.Checksum is {0}", tcp.Checksum);
            Assert.AreEqual(0xc835, tcp.Checksum, "tcp.Checksum mismatch");
            Assert.IsTrue(tcp.ValidTcpChecksum);
        }

        // tcp
        public void VerifyPacket1(Packet p, RawCapture rawCapture)
        {
            Console.WriteLine(p.ToString());

            var e = (EthernetPacket) p;
            Assert.AreEqual("0016CFC91E29", e.SourceHardwareAddress.ToString());
            Assert.AreEqual("0014BFF2EF0A", e.DestinationHardwareAddress.ToString());

            var ip = (IPPacket) p.PayloadPacket;
            Assert.AreEqual(System.Net.IPAddress.Parse("192.168.1.104"), ip.SourceAddress);
            Assert.AreEqual(System.Net.IPAddress.Parse("86.42.196.13"), ip.DestinationAddress);
            Assert.AreEqual(64, ip.TimeToLive);
            Assert.AreEqual(0x2ff4, ((IPv4Packet) ip).CalculateIPChecksum());
            Assert.AreEqual(1171483600, rawCapture.Timeval.Seconds);
            Assert.AreEqual(125234.000, rawCapture.Timeval.MicroSeconds);

            var tcp = (TcpPacket) ip.PayloadPacket;
            Assert.AreEqual(56925, tcp.SourcePort);
            Assert.AreEqual(50199, tcp.DestinationPort);
            Assert.IsTrue(tcp.Acknowledgment);
            Assert.IsTrue(tcp.Push);
            Assert.AreEqual(16666, tcp.WindowSize);
            Assert.AreEqual(0x9b02, tcp.CalculateTcpChecksum());
            Assert.AreEqual(0x9b02, tcp.Checksum);
            Assert.IsTrue(tcp.ValidTcpChecksum);
        }

        // udp
        public void VerifyPacket2(Packet p, RawCapture rawCapture)
        {
            Console.WriteLine(p.ToString());
            var e = (EthernetPacket) p;
            Assert.AreEqual("0014BFF2EF0A", e.SourceHardwareAddress.ToString());
            Assert.AreEqual("0016CFC91E29", e.DestinationHardwareAddress.ToString());

            var ip = p.Extract<IPPacket>();
            Assert.AreEqual(System.Net.IPAddress.Parse("172.210.164.56"), ip.SourceAddress);
            Assert.AreEqual(System.Net.IPAddress.Parse("192.168.1.104"), ip.DestinationAddress);
            Assert.AreEqual(IPVersion.IPv4, ip.Version);
            Assert.AreEqual(ProtocolType.Udp, ip.Protocol);
            Assert.AreEqual(112, ip.TimeToLive);
            Assert.AreEqual(0xe0a2, ((IPv4Packet) ip).CalculateIPChecksum());
            Assert.AreEqual(1171483602, rawCapture.Timeval.Seconds);
            Assert.AreEqual(578641.000, rawCapture.Timeval.MicroSeconds);

            var udp = p.Extract<UdpPacket>();
            Assert.AreEqual(52886, udp.SourcePort);
            Assert.AreEqual(56924, udp.DestinationPort);
            Assert.AreEqual(71, udp.Length);
            Assert.AreEqual(0xc8b8, udp.Checksum);
        }

        // dns
        public void VerifyPacket3(Packet p, RawCapture rawCapture)
        {
            Console.WriteLine(p.ToString());
            var e = (EthernetPacket) p;
            Assert.AreEqual("0016CFC91E29", e.SourceHardwareAddress.ToString());
            Assert.AreEqual("0014BFF2EF0A", e.DestinationHardwareAddress.ToString());

            var ip = p.Extract<IPPacket>();
            Assert.AreEqual(System.Net.IPAddress.Parse("192.168.1.172"), ip.SourceAddress);
            Assert.AreEqual(System.Net.IPAddress.Parse("66.189.0.29"), ip.DestinationAddress);
            Assert.AreEqual(ProtocolType.Udp, ip.Protocol);
            Assert.AreEqual(0x7988, ((IPv4Packet) ip).CalculateIPChecksum());

            var udp = p.Extract<UdpPacket>();
            Assert.AreEqual(3619, udp.SourcePort);
            Assert.AreEqual(53, udp.DestinationPort);
            Assert.AreEqual(47, udp.Length);
            Assert.AreEqual(0xbe2d, udp.Checksum);
        }

        // arp
        public void VerifyPacket4(Packet p, RawCapture rawCapture)
        {
            Console.WriteLine(p.ToString());
            var e = (EthernetPacket) p;
            Assert.AreEqual("0018F84B17A0", e.SourceHardwareAddress.ToString());
            Assert.AreEqual("FFFFFFFFFFFF", e.DestinationHardwareAddress.ToString());
        }

        // icmp
        public void VerifyPacket5(Packet p, RawCapture rawCapture)
        {
            Console.WriteLine(p.ToString());
            var e = (EthernetPacket) p;
            Assert.AreEqual("0016CFC91E29", e.SourceHardwareAddress.ToString());
            Assert.AreEqual("0014BFF2EF0A", e.DestinationHardwareAddress.ToString());

            var ip = p.Extract<IPPacket>();
            Assert.AreEqual(System.Net.IPAddress.Parse("192.168.1.104"), ip.SourceAddress);
            Assert.AreEqual(System.Net.IPAddress.Parse("85.195.52.22"), ip.DestinationAddress);
        }

        [Test]
        public void EthernetConstructorFromMacAddresses()
        {
            var srcHwAddressBytes = new byte[EthernetFields.MacAddressLength];
            for (var i = 0; i < srcHwAddressBytes.Length; i++)
                srcHwAddressBytes[i] = (byte) i;

            var dstHwAddressBytes = new byte[EthernetFields.MacAddressLength];
            for (var i = 0; i < dstHwAddressBytes.Length; i++)
                dstHwAddressBytes[i] = (byte) (dstHwAddressBytes.Length - i);

            var srcHwAddress = new PhysicalAddress(srcHwAddressBytes);
            var dstHwAddress = new PhysicalAddress(dstHwAddressBytes);
            var ethernetPacket = new EthernetPacket(srcHwAddress,
                                                    dstHwAddress,
                                                    EthernetType.None);

            Assert.AreEqual(14, ethernetPacket.Bytes.Length);
            Assert.AreEqual(srcHwAddress, ethernetPacket.SourceHardwareAddress);
            Assert.AreEqual(dstHwAddress, ethernetPacket.DestinationHardwareAddress);

            ethernetPacket.SourceHardwareAddress = dstHwAddress;
            ethernetPacket.DestinationHardwareAddress = srcHwAddress;

            Assert.AreEqual(dstHwAddress, ethernetPacket.SourceHardwareAddress);
            Assert.AreEqual(srcHwAddress, ethernetPacket.DestinationHardwareAddress);

            Console.WriteLine("ethernetPacket.ToString() {0}", ethernetPacket);
        }

        [Test]
        public void ParsingPacket()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "test_stream.pcap");
            dev.Open();

            PacketCapture c;
            dev.GetNextPacket(out c);
            var p = c.GetPacket();

            var e = new EthernetPacket(new ByteArraySegment(p.Data));
            Console.WriteLine("ethernet.ToString() {0}", e);

            Assert.AreEqual(PhysicalAddress.Parse("00-13-10-03-71-47"), e.SourceHardwareAddress);
            Assert.AreEqual(PhysicalAddress.Parse("00-E0-4C-E5-73-AD"), e.DestinationHardwareAddress);

            Assert.AreEqual(EthernetType.IPv4, e.Type);

            dev.Close();
        }

        [Test]
        public void PrintString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "test_stream.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            var status = dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var eth = (EthernetPacket) p;

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(eth.ToString());
        }

        [Test]
        public void PrintVerboseString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "test_stream.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            var status = dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var eth = (EthernetPacket) p;

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(eth.ToString(StringOutputType.Verbose));
        }

        [Test]
        public void RandomPacket()
        {
            EthernetPacket.RandomPacket();
        }

        /// <summary>
        /// Test parsing a handful of packets with known contents as verified by
        /// wireshark.
        /// </summary>
        [Test]
        public void TestParsingKnownPackets()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "test_stream.pcap");
            dev.Open();

            PacketCapture c;
            GetPacketStatus status;
            var packetIndex = 0;
            while ((status = dev.GetNextPacket(out c)) == GetPacketStatus.PacketRead)
            {
                var rawCapture = c.GetPacket();
                var p = Packet.ParsePacket(rawCapture.GetLinkLayers(),
                                           rawCapture.Data);

                switch (packetIndex)
                {
                    case 0:
                    {
                        VerifyPacket0(p, rawCapture);
                        break;
                    }
                    case 1:
                    {
                        VerifyPacket1(p, rawCapture);
                        break;
                    }
                    case 2:
                    {
                        VerifyPacket2(p, rawCapture);
                        break;
                    }
                    case 3:
                    {
                        VerifyPacket3(p, rawCapture);
                        break;
                    }
                    case 4:
                    {
                        VerifyPacket4(p, rawCapture);
                        break;
                    }
                    case 5:
                    {
                        VerifyPacket5(p, rawCapture);
                        break;
                    }
                    default:
                    {
                        Assert.Fail("didn't expect to get to packetIndex " + packetIndex);
                        break;
                    }
                }

                packetIndex++;
            }

            dev.Close();
        }
    }
}