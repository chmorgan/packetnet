/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/
/*
 * Copyright 2012 Alan Rushforth <alan.rushforth@gmail.com>
 */

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
    public class ActionFrameTest
    {
        /// <summary>
        /// Test that parsing a add block ack response report frame yields the proper field values
        /// </summary>
        [Test]
        public void Test_Constructor_AddBlockAckResponseReport()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "80211_block_ack_response_action_frame.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
            var frame = (ActionFrame) p.PayloadPacket;

            Assert.AreEqual(0, frame.FrameControl.ProtocolVersion);
            Assert.AreEqual(FrameControlField.FrameSubTypes.ManagementAction, frame.FrameControl.SubType);
            Assert.IsFalse(frame.FrameControl.ToDS);
            Assert.IsFalse(frame.FrameControl.FromDS);
            Assert.IsFalse(frame.FrameControl.MoreFragments);
            Assert.IsFalse(frame.FrameControl.Retry);
            Assert.IsFalse(frame.FrameControl.PowerManagement);
            Assert.IsFalse(frame.FrameControl.MoreData);
            Assert.IsFalse(frame.FrameControl.Protected);
            Assert.IsFalse(frame.FrameControl.Order);
            Assert.AreEqual(314, frame.Duration.Field); //this need expanding on in the future
            Assert.AreEqual("0024B2F8D706", frame.DestinationAddress.ToString().ToUpper());
            Assert.AreEqual("7CC5376D16E7", frame.SourceAddress.ToString().ToUpper());
            Assert.AreEqual("0024B2F8D706", frame.BssId.ToString().ToUpper());
            Assert.AreEqual(0, frame.SequenceControl.FragmentNumber);
            Assert.AreEqual(3826, frame.SequenceControl.SequenceNumber);

            Assert.AreEqual(0x6D3FCFA3, frame.FrameCheckSequence);
            Assert.AreEqual(24, frame.FrameSize);
            Assert.AreEqual(9, frame.PayloadData.Length);
        }

        [Test]
        public void Test_Constructor_ConstructWithValues()
        {
            var frame = new ActionFrame(PhysicalAddress.Parse("111111111111"),
                                        PhysicalAddress.Parse("222222222222"),
                                        PhysicalAddress.Parse("333333333333"))
            {
                FrameControl = { ToDS = false, FromDS = true, MoreFragments = true },
                SequenceControl = { SequenceNumber = 0x77, FragmentNumber = 0x1 },
                Duration = { Field = 0x1234 },
                PayloadData = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 }
            };

            frame.UpdateFrameCheckSequence();
            var fcs = frame.FrameCheckSequence;

            //serialize the frame into a byte buffer
            var bytes = frame.Bytes;
            var byteArraySegment = new ByteArraySegment(bytes);

            //create a new frame that should be identical to the original
            var recreatedFrame = MacFrame.ParsePacket(byteArraySegment) as ActionFrame;
            recreatedFrame.UpdateFrameCheckSequence();

            Assert.AreEqual(FrameControlField.FrameSubTypes.ManagementAction, recreatedFrame.FrameControl.SubType);
            Assert.IsFalse(recreatedFrame.FrameControl.ToDS);
            Assert.IsTrue(recreatedFrame.FrameControl.FromDS);
            Assert.IsTrue(recreatedFrame.FrameControl.MoreFragments);

            Assert.AreEqual(0x77, recreatedFrame.SequenceControl.SequenceNumber);
            Assert.AreEqual(0x1, recreatedFrame.SequenceControl.FragmentNumber);

            Assert.AreEqual("111111111111", recreatedFrame.SourceAddress.ToString().ToUpper());
            Assert.AreEqual("222222222222", recreatedFrame.DestinationAddress.ToString().ToUpper());
            Assert.AreEqual("333333333333", recreatedFrame.BssId.ToString().ToUpper());

            CollectionAssert.AreEqual(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 }, recreatedFrame.PayloadData);

            Assert.AreEqual(fcs, recreatedFrame.FrameCheckSequence);
        }

        [Test]
        public void Test_ConstructorWithCorruptBuffer()
        {
            //buffer is way too short for frame. We are just checking it doesn't throw
            byte[] corruptBuffer = { 0x01 };
            var frame = new ActionFrame(new ByteArraySegment(corruptBuffer));
            Assert.IsFalse(frame.FcsValid);
        }
    }
}