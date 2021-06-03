/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

using System;
using NUnit.Framework;
using PacketDotNet;
using SharpPcap.LibPcap;

namespace Test.PacketType
{
    [TestFixture]
    public class GreIPv4PacketTest
    {
        // GREIPv4
        [Test]
        public void GreIPv4Parsing()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "gre_all_options.pcap");
            dev.Open();
            var rawCapture = dev.GetNextPacket();
            dev.Close();

            LinkLayers linkLayers = rawCapture.GetLinkLayers();
            if (linkLayers == LinkLayers.Ethernet)
            {
                Console.WriteLine("Linklayer is ethernet");
                // Linklayer
                Packet p = Packet.ParsePacket(linkLayers, rawCapture.Data);
                Assert.IsNotNull(p);

                // Ethernet
                EthernetPacket eth = p.Extract<EthernetPacket>();
                Assert.IsNotNull(eth);
                if (eth.Type == EthernetType.IPv4)
                {
                    Console.WriteLine("IPv4 inside ethernet");
                    // IPv4
                    IPv4Packet ipv4 = eth.Extract<IPv4Packet>();
                    Assert.IsNotNull(ipv4);
                    if (ipv4.Protocol == ProtocolType.Gre)
                    {
                        Console.WriteLine("GRE inside IPv4");
                        // Gre
                        GrePacket grep = ipv4.Extract<GrePacket>();
                        Assert.IsNotNull(grep);

                        // String output
                        Console.WriteLine(grep.ToString());

                        // Get header
                        if (grep.HasCheckSum)
                        {
                            Console.WriteLine("GRE has checksum flag");
                        }
                        if (grep.HasKey)
                        {
                            Console.WriteLine("GRE has key flag");
                        }
                        if (grep.HasReserved)
                        {
                            Console.WriteLine("GRE has reserved flag");
                        }
                        if (grep.HasSequence)
                        {
                            Console.WriteLine("GRE has sequence flag");
                        }

                        Assert.AreEqual(grep.Protocol, EthernetType.IPv4);
                        
                    }
                }
            }
        }
    }
}