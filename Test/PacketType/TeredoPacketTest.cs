/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

using NUnit.Framework;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType
{
    [TestFixture]
    public class TeredoPacketTest
    {
        [Test]
        public void TeredoParsing()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "teredo.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            var ethernetPacket = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
            Assert.IsNotNull(ethernetPacket);
            Assert.AreEqual(typeof(EthernetPacket), ethernetPacket.GetType());

            var ip4Packet = ethernetPacket.PayloadPacket;
            Assert.IsNotNull(ip4Packet);
            Assert.AreEqual(typeof(IPv4Packet), ip4Packet.GetType());

            var udpPacket = ip4Packet.PayloadPacket;
            Assert.IsNotNull(udpPacket);
            Assert.AreEqual(typeof(UdpPacket), udpPacket.GetType());

            var tunneledIp6Packet = udpPacket.PayloadPacket;
            Assert.IsNotNull(tunneledIp6Packet);
            Assert.AreEqual(typeof(IPv6Packet), tunneledIp6Packet.GetType());

            var tunneledTcpPacket = tunneledIp6Packet.PayloadPacket;
            Assert.IsNotNull(tunneledTcpPacket);
            Assert.AreEqual(typeof(IcmpV6Packet), tunneledTcpPacket.GetType());
        }
    }
}