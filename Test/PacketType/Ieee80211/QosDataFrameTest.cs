/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/
/*
 * Copyright 2012 Alan Rushforth <alan.rushforth@gmail.com>
 */

using System;
using System.Net.NetworkInformation;
using NUnit.Framework;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using PacketDotNet.Utils;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType.Ieee80211
{
    [TestFixture]
    public class QosDataFrameTest
    {
        /// <summary>
        /// Test that parsing a QOS data frame yields the proper field values
        /// </summary>
        [Test]
        public void Test_Constructor()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "80211_qos_data_frame.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
            var frame = (QosDataFrame) p.PayloadPacket;

            Assert.AreEqual(0, frame.FrameControl.ProtocolVersion);
            Assert.AreEqual(FrameControlField.FrameSubTypes.QosData, frame.FrameControl.SubType);
            Assert.IsFalse(frame.FrameControl.ToDS);
            Assert.IsTrue(frame.FrameControl.FromDS);
            Assert.IsFalse(frame.FrameControl.MoreFragments);
            Assert.IsFalse(frame.FrameControl.Retry);
            Assert.IsFalse(frame.FrameControl.PowerManagement);
            Assert.IsFalse(frame.FrameControl.MoreData);
            Assert.IsTrue(frame.FrameControl.Protected);
            Assert.IsFalse(frame.FrameControl.Order);
            Assert.AreEqual(44, frame.Duration.Field);
            Assert.AreEqual("7CC5376D16E7", frame.DestinationAddress.ToString().ToUpper());
            Assert.AreEqual("0024B2F8D706", frame.BssId.ToString().ToUpper());
            Assert.AreEqual("0024B2F8D706", frame.SourceAddress.ToString().ToUpper());
            Assert.AreEqual(0, frame.SequenceControl.FragmentNumber);
            Assert.AreEqual(2, frame.SequenceControl.SequenceNumber);
            Assert.AreEqual(0x00, frame.QosControl);
            Assert.AreEqual(0x87311A87, frame.FrameCheckSequence);
            Assert.AreEqual(26, frame.FrameSize);

            //TODO: This isn't correct, it should be 44 or 48 bytes, not 0x34 (52), clearly something
            // isn't being properly accounted for in the QosDataFrame.
            Assert.AreEqual(0x34, frame.PayloadData.Length);
        }

        [Test]
        public void Test_Constructor_ConstructWithValues()
        {
            var frame = new QosDataFrame
            {
                FrameControl = { ToDS = false, FromDS = true, MoreFragments = true, Protected = true },
                SequenceControl = { SequenceNumber = 0x89, FragmentNumber = 0x1 },
                Duration = { Field = 0x1234 },
                QosControl = 0x9876,
                DestinationAddress = PhysicalAddress.Parse("111111111111"),
                SourceAddress = PhysicalAddress.Parse("222222222222"),
                BssId = PhysicalAddress.Parse("333333333333"),
                PayloadData = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 }
            };

            frame.UpdateFrameCheckSequence();
            var fcs = frame.FrameCheckSequence;

            //serialize the frame into a byte buffer
            var bytes = frame.Bytes;
            var byteArraySegment = new ByteArraySegment(bytes);

            //create a new frame that should be identical to the original
            var recreatedFrame = MacFrame.ParsePacket(byteArraySegment) as QosDataFrame;
            recreatedFrame.UpdateFrameCheckSequence();

            Assert.AreEqual(FrameControlField.FrameSubTypes.QosData, recreatedFrame.FrameControl.SubType);
            Assert.IsFalse(recreatedFrame.FrameControl.ToDS);
            Assert.IsTrue(recreatedFrame.FrameControl.FromDS);
            Assert.IsTrue(recreatedFrame.FrameControl.MoreFragments);

            Assert.AreEqual(0x89, recreatedFrame.SequenceControl.SequenceNumber);
            Assert.AreEqual(0x1, recreatedFrame.SequenceControl.FragmentNumber);
            Assert.AreEqual(0x9876, recreatedFrame.QosControl);

            Assert.AreEqual("111111111111", recreatedFrame.DestinationAddress.ToString().ToUpper());
            Assert.AreEqual("222222222222", recreatedFrame.SourceAddress.ToString().ToUpper());
            Assert.AreEqual("333333333333", recreatedFrame.BssId.ToString().ToUpper());

            CollectionAssert.AreEqual(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 }, recreatedFrame.PayloadData);

            Assert.AreEqual(fcs, recreatedFrame.FrameCheckSequence);
        }

        [Test]
        public void Test_ConstructorWithCorruptBuffer()
        {
            //buffer is way too short for frame. We are just checking it doesn't throw
            byte[] corruptBuffer = { 0x01 };
            var frame = new QosDataFrame(new ByteArraySegment(corruptBuffer));
            Assert.IsFalse(frame.FcsValid);
        }

        /// <summary>
        /// Test that a QosData frame containing a tcp packet can be properly parsed
        /// </summary>
        [Test]
        public void Test_QosDataFrameParsingWithIpV4Tcp()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "80211_qos_data_frame_ipv4_tcp.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            Packet p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data) as RadioPacket;

            // test that we can access the lowest level tcp packet
            var t = p.Extract<TcpPacket>();
            Assert.IsNotNull(t, "Expected t not to be null");

            Console.WriteLine(p.ToString(StringOutputType.Verbose));
        }
    }
}