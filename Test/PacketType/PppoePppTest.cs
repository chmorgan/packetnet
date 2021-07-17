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
    public class PppoePppTest
    {
        [Test]
        public void PrintString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "PPPoEPPP.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var pppoe = p.Extract<PppoePacket>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(pppoe.ToString());
        }

        [Test]
        public void PrintVerboseString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "PPPoEPPP.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var pppoe = p.Extract<PppoePacket>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(pppoe.ToString(StringOutputType.Verbose));
        }

        [Test]
        public void TestParsingPppoePppPacket()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "PPPoEPPP.pcap");
            dev.Open();

            // first packet is a udp packet
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var packet = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
            var udpPacket = packet.Extract<UdpPacket>();
            Assert.IsNotNull(udpPacket, "Expected a valid udp packet for the first packet");

            // second packet is the PPPoe Ptp packet
            dev.GetNextPacket(out c);
            rawCapture = c.GetPacket();
            packet = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
            var anotherUdpPacket = packet.Extract<UdpPacket>();
            Assert.IsNotNull(anotherUdpPacket, "Expected a valid udp packet for the second packet as well");

            dev.Close();
        }
    }
}