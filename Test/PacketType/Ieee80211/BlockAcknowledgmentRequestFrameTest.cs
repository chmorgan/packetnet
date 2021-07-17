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
    public class BlockAcknowledgmentRequestFrameTest
    {
        /// <summary>
        /// Test that parsing a block acknowledgment request frame yields the proper field values
        /// </summary>
        [Test]
        public void Test_Constructor()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "80211_block_acknowledgment_request_frame.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
            var frame = (BlockAcknowledgmentRequestFrame) p.PayloadPacket;

            Assert.AreEqual(0, frame.FrameControl.ProtocolVersion);
            Assert.AreEqual(FrameControlField.FrameSubTypes.ControlBlockAcknowledgmentRequest, frame.FrameControl.SubType);
            Assert.IsFalse(frame.FrameControl.ToDS);
            Assert.IsFalse(frame.FrameControl.FromDS);
            Assert.IsFalse(frame.FrameControl.MoreFragments);
            Assert.IsFalse(frame.FrameControl.Retry);
            Assert.IsFalse(frame.FrameControl.PowerManagement);
            Assert.IsFalse(frame.FrameControl.MoreData);
            Assert.IsFalse(frame.FrameControl.Protected);
            Assert.IsFalse(frame.FrameControl.Order);
            Assert.AreEqual(314, frame.Duration.Field); //this need expanding on in the future
            Assert.AreEqual("7CC5376D16E7", frame.ReceiverAddress.ToString().ToUpper());
            Assert.AreEqual("0024B2F8D706", frame.TransmitterAddress.ToString().ToUpper());

            Assert.AreEqual(BlockAcknowledgmentControlField.AcknowledgementPolicy.Delayed, frame.BlockAcknowledgmentControl.Policy);
            Assert.IsFalse(frame.BlockAcknowledgmentControl.MultiTid);
            Assert.IsTrue(frame.BlockAcknowledgmentControl.CompressedBitmap);
            Assert.AreEqual(0, frame.BlockAcknowledgmentControl.Tid);
            Assert.AreEqual(0x0000, frame.BlockAckStartingSequenceControl);

            Assert.AreEqual(0x471D197A, frame.FrameCheckSequence);
            Assert.AreEqual(20, frame.FrameSize);
        }

        [Test]
        public void Test_Constructor_ConstructWithValues()
        {
            var frame = new BlockAcknowledgmentRequestFrame(PhysicalAddress.Parse("111111111111"),
                                                            PhysicalAddress.Parse("222222222222"))
            {
                FrameControl = { ToDS = false, FromDS = true, MoreFragments = true },
                Duration = { Field = 0x1234 },
                BlockAcknowledgmentControl = { CompressedBitmap = true, Policy = BlockAcknowledgmentControlField.AcknowledgementPolicy.Delayed, Tid = 0xF },
                BlockAckStartingSequenceControl = 0x5678
            };

            frame.UpdateFrameCheckSequence();
            var fcs = frame.FrameCheckSequence;

            //serialize the frame into a byte buffer
            var bytes = frame.Bytes;
            var byteArraySegment = new ByteArraySegment(bytes);

            //create a new frame that should be identical to the original
            var recreatedFrame = MacFrame.ParsePacket(byteArraySegment) as BlockAcknowledgmentRequestFrame;
            recreatedFrame.UpdateFrameCheckSequence();

            Assert.AreEqual(FrameControlField.FrameSubTypes.ControlBlockAcknowledgmentRequest, recreatedFrame.FrameControl.SubType);
            Assert.IsFalse(recreatedFrame.FrameControl.ToDS);
            Assert.IsTrue(recreatedFrame.FrameControl.FromDS);
            Assert.IsTrue(recreatedFrame.FrameControl.MoreFragments);
            Assert.AreEqual(0x1234, recreatedFrame.Duration.Field);
            Assert.AreEqual(BlockAcknowledgmentControlField.AcknowledgementPolicy.Delayed,
                            recreatedFrame.BlockAcknowledgmentControl.Policy);

            Assert.AreEqual(0xF, recreatedFrame.BlockAcknowledgmentControl.Tid);
            Assert.IsTrue(recreatedFrame.BlockAcknowledgmentControl.CompressedBitmap);
            Assert.AreEqual(0x5678, recreatedFrame.BlockAckStartingSequenceControl);

            Assert.AreEqual("111111111111", recreatedFrame.TransmitterAddress.ToString().ToUpper());
            Assert.AreEqual("222222222222", recreatedFrame.ReceiverAddress.ToString().ToUpper());

            Assert.AreEqual(fcs, recreatedFrame.FrameCheckSequence);
        }

        [Test]
        public void Test_ConstructorWithCorruptBuffer()
        {
            //buffer is way too short for frame. We are just checking it doesn't throw
            byte[] corruptBuffer = { 0x01 };
            var frame = new BlockAcknowledgmentRequestFrame(new ByteArraySegment(corruptBuffer));
            Assert.IsFalse(frame.FcsValid);
        }
    }
}