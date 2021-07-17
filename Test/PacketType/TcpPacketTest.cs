/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using NUnit.Framework;
using PacketDotNet;
using PacketDotNet.Tcp;
using PacketDotNet.Utils;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType
{
    [TestFixture]
    public class TcpPacketTest
    {
        [Test]
        public void ByteLengthInternalLengthMismatch()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "tcp_with_extra_bytes.pcap");
            dev.Open();

            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Assert.IsNotNull(p);

            Console.WriteLine(p.GetType());
            var t = p.Extract<TcpPacket>();
            Assert.IsNotNull(t, "Expected t not to be null");

            // even though the packet has 6 bytes of extra data, the ip packet shows a size of
            // 40 and the ip header has a length of 20. The TCP header is also 20 bytes so
            // there should be zero bytes in the TCPData value
            var expectedTcpDataLength = 0;
            Assert.AreEqual(expectedTcpDataLength, t.PayloadData.Length);

            dev.Close();
        }

        [Test]
        public virtual void Checksum()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "tcp.pcap");
            dev.Open();

            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Assert.IsNotNull(p);

            Console.WriteLine(p.GetType());

            var t = p.Extract<TcpPacket>();
            Assert.IsNotNull(t, "Expected t to not be null");
            Console.WriteLine("Checksum: " + t.Checksum.ToString("X"));
            Assert.IsTrue(t.ValidChecksum, "ValidChecksum indicates invalid checksum");

            dev.Close();
        }

        [Test]
        public void CreationAndReparsing()
        {
            var tcpPacket = TcpPacket.RandomPacket();

            var tcpPacket2 = new TcpPacket(new ByteArraySegment(tcpPacket.Bytes));

            Console.WriteLine("tcpPacket {0}", tcpPacket);
            Console.WriteLine("tcpPacket2 {0}", tcpPacket2);
        }

        [Test]
        public void PayloadModification()
        {
            var s = "-++++=== HELLLLOOO ===++++-";
            var data = System.Text.Encoding.UTF8.GetBytes(s);

            //create random pkt
            var p = TcpPacket.RandomPacket();

            //replace pkt's data with our string
            p.PayloadData = data;

            //sanity check
            Assert.AreEqual(s, System.Text.Encoding.Default.GetString(p.PayloadData));
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
            var t = p.Extract<TcpPacket>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(t.ToString());
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
            var t = p.Extract<TcpPacket>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(t.ToString(StringOutputType.Verbose));
        }

        [Test]
        public void RandomPacket()
        {
            TcpPacket.RandomPacket();
        }

        [Test]
        public void TCPConstructorFromValues()
        {
            ushort sourcePort = 100;
            ushort destinationPort = 101;
            var tcpPacket = new TcpPacket(sourcePort, destinationPort);

            Assert.AreEqual(sourcePort, tcpPacket.SourcePort);
            Assert.AreEqual(destinationPort, tcpPacket.DestinationPort);
        }

        [Test]
        public void TCPOptions()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "tcp.pcap");
            dev.Open();

            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Assert.IsNotNull(p);

            var t = p.Extract<TcpPacket>();
            Assert.IsNotNull(t, "Expected t to not be null");

            // verify that the options byte match what we expect
            byte[] expectedOptions =
            {
                0x1, 0x1, 0x8, 0xa, 0x0, 0x14,
                0x3d, 0xe5, 0x1d, 0xf5, 0xf8, 0x84
            };

            Assert.AreEqual(expectedOptions, t.Options);

            var options = t.OptionsCollection;

            Assert.AreEqual(true, options.Any(x => x is TimeStampOption));

            foreach (var option in options)
            {
                if (option is TimeStampOption timeStamp)
                {
                    Assert.AreEqual(1326565, timeStamp.Value);

                    timeStamp.Value = 1234321;

                    Assert.AreEqual(1234321, timeStamp.Value);
                }
            }

            var optionsCollection = new List<TcpOption>(options);
            t.OptionsCollection = optionsCollection;

            foreach (var option in t.OptionsCollection)
            {
                if (option is TimeStampOption timeStamp)
                {
                    Assert.AreEqual(1234321, timeStamp.Value);
                }
            }

            dev.Close();
        }

        /// <summary>
        /// Test that TSO works, see http://en.wikipedia.org/wiki/TCP_offload_engine
        /// </summary>
        [Test]
        public void TcpSegmentOffload()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "ipv4_tso_frame.pcap");
            dev.Open();

            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Assert.IsNotNull(p);

            var t = p.Extract<TcpPacket>();
            Assert.IsNotNull(t, "Expected t to not be null");

            dev.Close();
        }
    }
}