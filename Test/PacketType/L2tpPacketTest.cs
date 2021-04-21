/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

using System;
using NUnit.Framework;
using PacketDotNet;
using PacketDotNet.Utils.Converters;
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
            var rawCapture = dev.GetNextPacket();
            dev.Close();

            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Assert.IsNotNull(p);

            var l2tp = p.Extract<L2tpPacket>();
            Assert.AreEqual(l2tp.TunnelID, 18994);
            Assert.AreEqual(l2tp.SessionID, 54110);
            Console.WriteLine(l2tp.GetType());
        }


        // L2TP
        [Test]
        public void L2tp_SessionID()
        {
            var p = new L2tpPacket(new PacketDotNet.Utils.ByteArraySegment(new byte[8]
                { 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xa0 }),
                new NullPacket(NullPacketType.IPv4));

            Assert.IsNotNull(p);

            var l2tp = p.Extract<L2tpPacket>();
            Assert.AreEqual(l2tp.TunnelID, 0);
            Assert.That(EndianBitConverter.Big.ToUInt16(l2tp.Bytes, 6), Is.EqualTo(4000));
            Assert.That(EndianBitConverter.Big.ToUInt32(l2tp.Bytes, 4), Is.EqualTo(4000));
            Assert.AreEqual(l2tp.SessionID, 4000);
            Console.WriteLine(l2tp.GetType());
        }
    }
}