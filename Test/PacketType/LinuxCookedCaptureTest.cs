/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

using System;
using NUnit.Framework;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType
{
    [TestFixture]
    public class LinuxCookedCaptureTest
    {
        private void VerifyPacket0(Packet p)
        {
            // expect an arp packet
            var arpPacket = p.Extract<ArpPacket>();
            Assert.IsNotNull(arpPacket, "Expected arpPacket to not be null");

            // validate some of the LinuxSSLPacket fields
            var l = (LinuxSllPacket) p;
            Assert.AreEqual(6, l.LinkLayerAddressLength, "Address length");
            Assert.AreEqual(1, l.LinkLayerAddressType);
            Assert.AreEqual(LinuxSllType.PacketSentToUs, l.Type);

            // validate some of the arp fields
            Assert.AreEqual("192.168.1.1",
                            arpPacket.SenderProtocolAddress.ToString(),
                            "Arp SenderProtocolAddress");

            Assert.AreEqual("192.168.1.102",
                            arpPacket.TargetProtocolAddress.ToString(),
                            "Arp TargetProtocolAddress");
        }

        private void VerifyPacket1(Packet p)
        {
            // expect a udp packet
            Assert.IsNotNull(p.Extract<UdpPacket>(), "expected a udp packet");
        }

        private void VerifyPacket2(Packet p)
        {
            // expecting a tcp packet
            Assert.IsNotNull(p.Extract<TcpPacket>(), "expected a tcp packet");
        }

        [Test]
        public void CookedCaptureTest()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "LinuxCookedCapture.pcap");
            dev.Open();

            PacketCapture e;
            GetPacketStatus status;
            var packetIndex = 0;
            while ((status = dev.GetNextPacket(out e)) == GetPacketStatus.PacketRead)
            {
                var rawCapture = e.GetPacket();
                var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
                switch (packetIndex)
                {
                    case 0:
                    {
                        VerifyPacket0(p);
                        break;
                    }
                    case 1:
                    {
                        VerifyPacket1(p);
                        break;
                    }
                    case 2:
                    {
                        VerifyPacket2(p);
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

        [Test]
        public void PrintString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "LinuxCookedCapture.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var l = (LinuxSllPacket) p;

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(l.ToString());
        }

        [Test]
        public void PrintVerboseString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "LinuxCookedCapture.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var l = (LinuxSllPacket) p;

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(l.ToString(StringOutputType.Verbose));
        }
    }
}