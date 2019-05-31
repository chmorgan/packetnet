/*
This file is part of PacketDotNet

PacketDotNet is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

PacketDotNet is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with PacketDotNet.  If not, see <http://www.gnu.org/licenses/>.
*/
/*
 *  Copyright 2010 Chris Morgan <chmorgan@gmail.com>
 */

using System;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.Serialization.Formatters.Binary;
using NUnit.Framework;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType
{
    [TestFixture]
    public class ArpPacketTest
    {
        // arp request
        private void VerifyPacket0(Packet p)
        {
            var arpPacket = p.Extract<ArpPacket>();
            Assert.IsNotNull(arpPacket, "Expected arpPacket to not be null");

            var senderIp = IPAddress.Parse("192.168.1.202");
            var targetIp = IPAddress.Parse("192.168.1.214");

            Assert.AreEqual(senderIp, arpPacket.SenderProtocolAddress);
            Assert.AreEqual(targetIp, arpPacket.TargetProtocolAddress);

            var senderMacAddress = "000461990154";
            var targetMacAddress = "000000000000";
            Assert.AreEqual(senderMacAddress, arpPacket.SenderHardwareAddress.ToString());
            Assert.AreEqual(targetMacAddress, arpPacket.TargetHardwareAddress.ToString());
        }

        // arp response
        private void VerifyPacket1(Packet p)
        {
            var arp = p.Extract<ArpPacket>();
            Assert.IsNotNull(arp, "Expected arpPacket to not be null");

            var senderIp = IPAddress.Parse("192.168.1.214");
            var targetIp = IPAddress.Parse("192.168.1.202");

            Assert.AreEqual(senderIp, arp.SenderProtocolAddress);
            Assert.AreEqual(targetIp, arp.TargetProtocolAddress);

            var senderMacAddress = "00216A020854";
            var targetMacAddress = "000461990154";
            Assert.AreEqual(senderMacAddress, arp.SenderHardwareAddress.ToString());
            Assert.AreEqual(targetMacAddress, arp.TargetHardwareAddress.ToString());
        }

        [Test]
        public void BinarySerialization()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "arp_request_response.pcap");
            dev.Open();

            RawCapture rawCapture;
            var foundARP = false;
            while ((rawCapture = dev.GetNextPacket()) != null)
            {
                var p = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);

                var arp = p.Extract<ArpPacket>();
                if (arp == null)
                {
                    continue;
                }

                foundARP = true;

                var memoryStream = new MemoryStream();
                var serializer = new BinaryFormatter();
                serializer.Serialize(memoryStream, arp);

                memoryStream.Seek(0, SeekOrigin.Begin);
                var deserializer = new BinaryFormatter();
                var fromFile = (ArpPacket) deserializer.Deserialize(memoryStream);

                CollectionAssert.AreEqual(arp.Bytes, fromFile.Bytes);
                Assert.AreEqual(arp.BytesSegment.Bytes, fromFile.BytesSegment.Bytes);
                Assert.AreEqual(arp.BytesSegment.BytesLength, fromFile.BytesSegment.BytesLength);
                Assert.AreEqual(arp.BytesSegment.Length, fromFile.BytesSegment.Length);
                Assert.AreEqual(arp.BytesSegment.NeedsCopyForActualBytes, fromFile.BytesSegment.NeedsCopyForActualBytes);
                Assert.AreEqual(arp.BytesSegment.Offset, fromFile.BytesSegment.Offset);
                Assert.AreEqual(arp.Color, fromFile.Color);
                Assert.AreEqual(arp.HardwareAddressLength, fromFile.HardwareAddressLength);
                Assert.AreEqual(arp.HardwareAddressType, fromFile.HardwareAddressType);
                CollectionAssert.AreEqual(arp.HeaderData, fromFile.HeaderData);
                Assert.AreEqual(arp.Operation, fromFile.Operation);
                Assert.AreEqual(arp.ParentPacket, fromFile.ParentPacket);
                CollectionAssert.AreEqual(arp.PayloadData, fromFile.PayloadData);
                Assert.AreEqual(arp.PayloadPacket, fromFile.PayloadPacket);
                Assert.AreEqual(arp.ProtocolAddressLength, fromFile.ProtocolAddressLength);
                Assert.AreEqual(arp.ProtocolAddressType, fromFile.ProtocolAddressType);
                Assert.AreEqual(arp.SenderHardwareAddress, fromFile.SenderHardwareAddress);
                Assert.AreEqual(arp.SenderProtocolAddress, fromFile.SenderProtocolAddress);
                Assert.AreEqual(arp.TargetHardwareAddress, fromFile.TargetHardwareAddress);
                Assert.AreEqual(arp.TargetProtocolAddress, fromFile.TargetProtocolAddress);

                //Method Invocations to make sure that a deserialized packet does not cause 
                //additional errors.

                arp.PrintHex();
                arp.UpdateCalculatedValues();
            }

            dev.Close();

            Assert.IsTrue(foundARP, "Capture file contained no ARP packets");
        }

        /// <summary>
        /// Test that we can build an ArpPacket from values
        /// </summary>
        [Test]
        public void ConstructingFromValues()
        {
            var localIPBytes = new byte[] { 124, 10, 10, 20 };
            var localIP = new IPAddress(localIPBytes);

            var destinationIPBytes = new byte[] { 192, 168, 1, 10 };
            var destinationIP = new IPAddress(destinationIPBytes);

            var localMac = PhysicalAddress.Parse("AA-BB-CC-DD-EE-FF");

            var _ = new ArpPacket(ArpOperation.Request,
                                  PhysicalAddress.Parse("00-00-00-00-00-00"),
                                  destinationIP,
                                  localMac,
                                  localIP);
        }

        [Test]
        public void ParsingArpPacketRequestResponse()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "arp_request_response.pcap");
            dev.Open();

            RawCapture rawCapture;
            var packetIndex = 0;
            while ((rawCapture = dev.GetNextPacket()) != null)
            {
                var p = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);

                Console.WriteLine("got packet");
                Console.WriteLine("{0}", p);
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
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "arp_request_response.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            var rawCapture = dev.GetNextPacket();
            var p = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);

            Console.WriteLine("Parsing");
            var arp = p.Extract<ArpPacket>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(arp.ToString());
        }

        [Test]
        public void PrintVerboseString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "arp_request_response.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            var rawCapture = dev.GetNextPacket();
            var p = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);

            Console.WriteLine("Parsing");
            var arp = p.Extract<ArpPacket>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(arp.ToString(StringOutputType.Verbose));
        }
    }
}