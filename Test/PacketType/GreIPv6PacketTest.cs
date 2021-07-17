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
    public class GreIPv6PacketTest
    {
        // GREIPv6
        [Test]
        public void GreIPv6Parsing()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "gre_ipv6.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Assert.IsNotNull(p);

            var gerp = p.Extract<GrePacket>();
            Assert.AreEqual(gerp.Protocol, EthernetType.IPv6);
            Console.WriteLine(gerp.GetType());
        }
    }
}