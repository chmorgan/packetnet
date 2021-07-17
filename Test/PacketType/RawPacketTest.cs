/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

using System;
using NUnit.Framework;
using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;

namespace Test.PacketType
{
    [TestFixture]
    public class RawPacketTest
    {
        [Test]
        public void PrintString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new SharpPcap.LibPcap.CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "arp_request_response.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            dev.GetNextPacket(out c);
            var rawPacket = c.GetPacket();
            dev.Close();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(rawPacket.ToString());
        }
    }
}