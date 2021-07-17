/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/
/*
 * Copyright 2010 Evan Plaice <evanplaice@gmail.com>
 * Copyright 2010 Chris Morgan <chmorgan@gmail.com>
 */

using System;
using System.Net.NetworkInformation;
using NUnit.Framework;
using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType
{
    [TestFixture]
    public class WakeOnLanTest
    {
        [Test]
        public void CreateFromValues()
        {
            var physicalAddress = PhysicalAddress.Parse("CA-FE-BA-BE-C0-01");
            var wol = new WakeOnLanPacket(physicalAddress);

            Assert.IsTrue(wol.IsValid());
            Assert.AreEqual(wol.DestinationAddress, physicalAddress);

            // convert the wol packet back into bytes
            var wolBytes = wol.Bytes;

            // and now parse it back from bytes into a wol packet
            var wol2 = new WakeOnLanPacket(new ByteArraySegment(wolBytes));

            // make sure the packets match
            Assert.AreEqual(wol, wol2);
        }

        [Test]
        public void PrintString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "wol.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var wol = p.Extract<WakeOnLanPacket>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(wol.ToString());
        }

        [Test]
        public void PrintVerboseString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "wol.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var wol = p.Extract<WakeOnLanPacket>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(wol.ToString(StringOutputType.Verbose));
        }

        [Test]
        public void RandomPacket()
        {
            WakeOnLanPacket.RandomPacket();
        }

        [Test]
        public void WakeOnLanParsing()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "wol.pcap");
            dev.Open();

            PacketCapture c;
            GetPacketStatus status;
            var packetIndex = 0;
            while ((status = dev.GetNextPacket(out c)) == GetPacketStatus.PacketRead)
            {
                var rawCapture = c.GetPacket();

                var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
                Assert.IsNotNull(p);

                var wol = p.Extract<WakeOnLanPacket>();
                Assert.IsNotNull(p);

                if (packetIndex == 0)
                    Assert.AreEqual(wol.DestinationAddress, PhysicalAddress.Parse("00-0D-56-DC-9E-35"));

                if (packetIndex == 3)
                    Assert.AreEqual(wol.DestinationAddress, PhysicalAddress.Parse("00-90-27-85-CF-01"));

                packetIndex++;
            }

            dev.Close();
        }

        [Test]
        public void PasswordChecking()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "wol.pcap");
            dev.Open();

            GetPacketStatus status;
            PacketCapture c;

            var packetIndex = 0;
            while ((status = dev.GetNextPacket(out c)) == GetPacketStatus.PacketRead)
            {
                var rawCapture = c.GetPacket();

                var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
                Assert.IsNotNull(p);

                var wol = p.Extract<WakeOnLanPacket>();
                Assert.IsNotNull(p);

                if (packetIndex == 0|| packetIndex == 3)
                    Assert.AreEqual(wol.Password, new byte[0]);

                if (packetIndex == 1)
                    Assert.AreEqual(wol.Password, new byte[] { 0xc0, 0xa8, 0x01, 0x01 });

                if (packetIndex == 2)
                    Assert.AreEqual(wol.Password, new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab });
                
                packetIndex++;
            }

            dev.Close();
        }
    }
}