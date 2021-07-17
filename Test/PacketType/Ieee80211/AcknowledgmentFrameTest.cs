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
    public class AcknowledgmentFrameTest
    {
        [Test]
        public void Test_Constructor()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "80211_ack_frame.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
            var frame = (AcknowledgmentFrame) p.PayloadPacket;

            Assert.AreEqual(0, frame.FrameControl.ProtocolVersion);
            Assert.AreEqual(FrameControlField.FrameSubTypes.ControlAck, frame.FrameControl.SubType);
            Assert.IsFalse(frame.FrameControl.ToDS);
            Assert.IsFalse(frame.FrameControl.FromDS);
            Assert.IsFalse(frame.FrameControl.MoreFragments);
            Assert.IsFalse(frame.FrameControl.Retry);
            Assert.IsFalse(frame.FrameControl.PowerManagement);
            Assert.IsFalse(frame.FrameControl.MoreData);
            Assert.IsFalse(frame.FrameControl.Protected);
            Assert.IsFalse(frame.FrameControl.Order);
            Assert.AreEqual(0, frame.Duration.Field); //this need expanding on in the future
            Assert.AreEqual("F8DB7F491342", frame.ReceiverAddress.ToString().ToUpper());
            Assert.AreEqual(0xD2F5BE07, frame.FrameCheckSequence);
            Assert.AreEqual(10, frame.FrameSize);
        }

        [Test]
        public void Test_Constructor_ConstructWithValues()
        {
            var frame = new AcknowledgmentFrame(PhysicalAddress.Parse("111111111111"))
            {
                FrameControl = { ToDS = false, FromDS = true, MoreFragments = true },
                Duration = { Field = 0x1234 }
            };

            frame.UpdateFrameCheckSequence();
            var fcs = frame.FrameCheckSequence;

            //serialize the frame into a byte buffer
            var bytes = frame.Bytes;
            var byteArraySegment = new ByteArraySegment(bytes);

            //create a new frame that should be identical to the original
            var recreatedFrame = MacFrame.ParsePacket(byteArraySegment) as AcknowledgmentFrame;
            recreatedFrame.UpdateFrameCheckSequence();

            Assert.AreEqual(FrameControlField.FrameSubTypes.ControlAck, recreatedFrame.FrameControl.SubType);
            Assert.IsFalse(recreatedFrame.FrameControl.ToDS);
            Assert.IsTrue(recreatedFrame.FrameControl.FromDS);
            Assert.IsTrue(recreatedFrame.FrameControl.MoreFragments);

            Assert.AreEqual("111111111111", recreatedFrame.ReceiverAddress.ToString().ToUpper());

            Assert.AreEqual(fcs, recreatedFrame.FrameCheckSequence);
        }

        [Test]
        public void Test_ConstructorWithCorruptBuffer()
        {
            //buffer is way too short for frame. We are just checking it doesn't throw
            byte[] corruptBuffer = { 0x01 };
            var frame = new AcknowledgmentFrame(new ByteArraySegment(corruptBuffer));
            Assert.IsFalse(frame.FcsValid);
        }
    }
}