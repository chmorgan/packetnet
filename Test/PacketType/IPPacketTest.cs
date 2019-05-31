/*
This file is part of PacketDotNet

PacketDotNet is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

PacketDotNet is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with PacketDotNet.  If not, see <http://www.gnu.org/licenses/>.
*/
/*
 *  Copyright 2010 Chris Morgan <chmorgan@gmail.com>
 */

using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using NUnit.Framework;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType
{
    [TestFixture]
    public class IPPacketTest
    {
        [Test]
        public void IpPacket_WhenGettingPacketFragment_LeavesPacketAsPayload()
        {
            // Arrange
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "udp-ip-fragmented.pcap");
            dev.Open();
            var firstRawPacket = dev.GetNextPacket();
            var secondRawPacket = dev.GetNextPacket();
            dev.Close();

            // Act
            Packet.ParsePacket(firstRawPacket.LinkLayerType, firstRawPacket.Data); // read and discard first packet
            var secondPacket = Packet.ParsePacket(secondRawPacket.LinkLayerType, secondRawPacket.Data);
            var ip = secondPacket.Extract<IPPacket>();

            // Assert
            Assert.IsNotNull(ip, "The second packet should contain an IP packet within");
            Assert.IsNull(ip.PayloadPacket, "Since packet is IP fragment, we should not have extracted a child packet");
            Assert.AreEqual(497, ip.PayloadLength, "The correct payload length for this particular packet should be 497");
            Assert.AreEqual(497, ip.PayloadData.Length, "The correct payload length for this particular packet should be 497");
        }

        [Test]
        public void IpPacket_WhenGettingPacketThatIsNotAFragment_ParsesPacketProperly()
        {
            // Arrange
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "udp-ip-fragmented.pcap");
            dev.Open();
            var firstRawPacket = dev.GetNextPacket();
            dev.Close();

            // Act
            var firstPacket = Packet.ParsePacket(firstRawPacket.LinkLayerType, firstRawPacket.Data);
            var ip = firstPacket.Extract<IPPacket>();
            var udpPacket = ip.Extract<UdpPacket>();

            // Assert
            Assert.IsNotNull(ip, "The packet should contain an IP packet within");
            Assert.IsNotNull(ip.PayloadPacket, "This is not a fragment, and should contain an UDP packet");
            Assert.IsNotNull(udpPacket, "We should have a UDP packet in there");
            Assert.AreEqual(1977, udpPacket.Length, "We should have the proper length for the packet");
            Assert.AreEqual(5060, udpPacket.DestinationPort, "We should have extracted the correct destination port");
            Assert.AreEqual(5060, udpPacket.SourcePort, "We should have extracted the correct source port");
        }

        /// <summary>
        /// Test that parsing an ip packet yields the proper field values
        /// </summary>
        [Test]
        public void IpPacketFields()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "tcp.pcap");
            dev.Open();
            var rawCapture = dev.GetNextPacket();
            dev.Close();

            var p = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);

            Assert.IsNotNull(p);

            var ip = p.Extract<IPPacket>();
            Console.WriteLine(ip.GetType());

            Assert.AreEqual(20, ip.HeaderData.Length, "Header.Length doesn't match expected length");
            Console.WriteLine(ip.ToString());
        }
    }
}