﻿/*
This file is part of PacketDotNet

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/
/*
 *  Copyright 2017 Chris Morgan <chmorgan@gmail.com>
 */

using System;
using NUnit.Framework;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType
{
    [TestFixture]
    public class LinkTypeNullCaptureTest
    {
        private static void VerifyPacket0(Packet p)
        {
            Assert.AreEqual(p.PayloadPacket.GetType(), typeof(IPv4Packet));
            Assert.AreEqual(p.PayloadPacket.PayloadPacket.GetType(), typeof(TcpPacket));
        }

        private static void VerifyPacket1(Packet p)
        {
            Assert.AreEqual(p.PayloadPacket.GetType(), typeof(IPv6Packet));
            Assert.AreEqual(p.PayloadPacket.PayloadPacket.GetType(), typeof(TcpPacket));
        }

        [Test]
        public void LinkTypeOfNullCaptureTest()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "linktype_null_capture.pcap");
            dev.Open();

            RawCapture rawCapture;
            var packetIndex = 0;
            while ((rawCapture = dev.GetNextPacket()) != null)
            {
                Console.WriteLine("LinkLayers: {0}", rawCapture.GetLinkLayers());
                var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
                switch (packetIndex)
                {
                    case 0:
                    {
                        VerifyPacket0(p);
                        break;
                    }
                    case 1:
                    {
                        VerifyPacket1(p);
                        break;
                    }
                    default:
                    {
                        Assert.Fail("didn't expect to get to packetIndex " + packetIndex);
                        break;
                    }
                }

                packetIndex++;
            }

            dev.Close();
        }

        [Test]
        public void PrintString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "linktype_null_capture.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            var rawCapture = dev.GetNextPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var np = (NullPacket) p;

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(np.ToString());
        }

        [Test]
        public void PrintVerboseString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "linktype_null_capture.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            var rawCapture = dev.GetNextPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var np = (NullPacket) p;

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(np.ToString(StringOutputType.Verbose));
        }
    }
}