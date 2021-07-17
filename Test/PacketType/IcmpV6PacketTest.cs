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
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType
{
    [TestFixture]
    public class IcmpV6PacketTest
    {
        /// <summary>
        /// Test that the checksum can be recalculated properly
        /// </summary>
        [Test]
        public void Checksum()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "ipv6_icmpv6_packet.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            // save the checksum
            var icmpv6 = p.Extract<IcmpV6Packet>();
            Assert.IsNotNull(icmpv6);
            var savedChecksum = icmpv6.Checksum;

            // now zero the checksum out
            icmpv6.Checksum = 0;

            // and recalculate the checksum
            icmpv6.UpdateCalculatedValues();

            // compare the checksum values to ensure that they match
            Assert.AreEqual(savedChecksum, icmpv6.Checksum);
        }

        /// <summary>
        /// Test that we can parse a icmp v4 request and reply
        /// </summary>
        [Test]
        public void IcmpV6Parsing()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "ipv6_icmpv6_packet.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Assert.IsNotNull(p);

            var icmpv6 = p.Extract<IcmpV6Packet>();
            Console.WriteLine(icmpv6.GetType());

            Assert.AreEqual(IcmpV6Type.RouterSolicitation, icmpv6.Type);
            Assert.AreEqual(0, icmpv6.Code);
            Assert.AreEqual(0x5d50, icmpv6.Checksum);

            // Payload differs based on the icmp.Type field
        }

        [Test]
        public void PrintString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "ipv6_icmpv6_packet.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var icmpv6 = p.Extract<IcmpV6Packet>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(icmpv6.ToString());
        }

        [Test]
        public void PrintVerboseString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "ipv6_icmpv6_packet.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var icmpV6 = p.Extract<IcmpV6Packet>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(icmpV6.ToString(StringOutputType.Verbose));
        }
    }
}