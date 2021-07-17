/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using NUnit.Framework;
using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType
{
    [TestFixture]
    public class IPv4PacketTest
    {
        [Test]
        public void ConstructingFromValues()
        {
            var sourceAddress = RandomUtils.GetIPAddress(IPVersion.IPv4);
            var destinationAddress = RandomUtils.GetIPAddress(IPVersion.IPv4);
            var ip = new IPv4Packet(sourceAddress, destinationAddress);

            Assert.AreEqual(sourceAddress, ip.SourceAddress);
            Assert.AreEqual(destinationAddress, ip.DestinationAddress);

            // make sure the version is what we expect
            Assert.AreEqual(IPv4Packet.IPVersion, ip.Version);

            // retrieve the bytes for this IPv4Packet and construct another IPv4 packet from
            // these bytes
            var bytes = ip.Bytes;
            var ip2 = new IPv4Packet(new ByteArraySegment(bytes));

            // compare some of the the values
            //TODO: add more values here or implement an IPv4Packet equals method and use that here
            Assert.AreEqual(ip.Version, ip2.Version);
        }

        [Test]
        public void ChangeValues()
        {
            var packet = IPv4Packet.RandomPacket();
            packet.Id = 12345;
            Assert.AreEqual(12345, packet.Id);
        }

        [Test]
        public void PrintString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "tcp.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var ip = p.Extract<IPv4Packet>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(ip.ToString());
        }

        [Test]
        public void PrintVerboseString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "tcp.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var ip = p.Extract<IPv4Packet>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(ip.ToString(StringOutputType.Verbose));
        }

        [Test]
        public void RandomPacket()
        {
            IPv4Packet.RandomPacket();
        }
    }
}