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
 *  Copyright 2010 Evan Plaice <evanplaice@gmail.com>
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
    public class PppPacketTest
    {
        [Test]
        public void BinarySerialization()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "PPPoEPPP.pcap");
            dev.Open();

            RawCapture rawCapture;
            var foundPPP = false;
            while ((rawCapture = dev.GetNextPacket()) != null)
            {
                var p = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
                var ppp = p.Extract<PppPacket>();

                if (ppp == null)
                {
                    continue;
                }

                foundPPP = true;

                var memoryStream = new MemoryStream();
                var serializer = new BinaryFormatter();
                serializer.Serialize(memoryStream, ppp);

                memoryStream.Seek(0, SeekOrigin.Begin);
                var deserializer = new BinaryFormatter();
                var fromFile = (PppPacket) deserializer.Deserialize(memoryStream);

                Assert.AreEqual(ppp.Bytes, fromFile.Bytes);
                Assert.AreEqual(ppp.BytesSegment.Bytes, fromFile.BytesSegment.Bytes);
                Assert.AreEqual(ppp.BytesSegment.BytesLength, fromFile.BytesSegment.BytesLength);
                Assert.AreEqual(ppp.BytesSegment.Length, fromFile.BytesSegment.Length);
                Assert.AreEqual(ppp.BytesSegment.NeedsCopyForActualBytes, fromFile.BytesSegment.NeedsCopyForActualBytes);
                Assert.AreEqual(ppp.BytesSegment.Offset, fromFile.BytesSegment.Offset);
                Assert.AreEqual(ppp.Color, fromFile.Color);
                Assert.AreEqual(ppp.HeaderData, fromFile.HeaderData);
                Assert.AreEqual(ppp.PayloadData, fromFile.PayloadData);
                Assert.AreEqual(ppp.Protocol, fromFile.Protocol);

                //Method Invocations to make sure that a deserialized packet does not cause 
                //additional errors.

                ppp.UpdateCalculatedValues();
            }

            dev.Close();

            Assert.IsTrue(foundPPP, "Capture file contained no PPP packets");
        }

        [Test]
        public void PrintString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "PPPoEPPP.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            dev.GetNextPacket();
            var rawCapture = dev.GetNextPacket();
            dev.Close();
            var p = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);

            Console.WriteLine("Parsing");
            var ppp = p.Extract<PppPacket>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(ppp.ToString());
        }

        [Test]
        public void PrintVerboseString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "PPPoEPPP.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            dev.GetNextPacket();
            var rawCapture = dev.GetNextPacket();
            dev.Close();
            var p = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);

            Console.WriteLine("Parsing");
            var ppp = p.Extract<PppPacket>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(ppp.ToString(StringOutputType.Verbose));
        }
    }
}