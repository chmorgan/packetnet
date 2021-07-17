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
    public class L2tpPacketTest
    {
        // L2TP
        [Test]
        public void L2tpParsing()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "l2tp.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Assert.IsNotNull(p);

            var l2tp = p.Extract<L2tpPacket>();
            Assert.AreEqual(l2tp.TunnelID, 18994);
            Assert.AreEqual(l2tp.SessionID, 54110);
            Console.WriteLine(l2tp.GetType());
        }
    }
}