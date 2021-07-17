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
    public class Vlan802_1QTest
    {
        /// <summary>
        /// Test that a vlan packet can be properly parsed
        /// </summary>
        [Test]
        public void ParsingVlanPacket()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "802.1q_vlan_ipv4_tcp.pcap");
            dev.Open();

            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();

            Console.WriteLine("Parsing");
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(p.ToString(StringOutputType.Verbose));

            var vlanTag = p.Extract<Ieee8021QPacket>();
            Assert.AreEqual(IeeeP8021PPriority.BestEffort, vlanTag.PriorityControlPoint);
            var tagId = 102;
            Assert.AreEqual(tagId, vlanTag.VlanIdentifier);
            Assert.AreEqual(false, vlanTag.CanonicalFormatIndicator);
        }
    }
}