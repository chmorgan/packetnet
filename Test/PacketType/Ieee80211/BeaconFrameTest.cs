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
    public class BeaconFrameTest
    {
        /// <summary>
        /// Test that parsing an ip packet yields the proper field values
        /// </summary>
        [Test]
        public void ReadingPacketsFromFile()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "80211_beacon_frame.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
            var beaconFrame = (BeaconFrame) p.PayloadPacket;

            Assert.AreEqual(0, beaconFrame.FrameControl.ProtocolVersion);
            Assert.AreEqual(FrameControlField.FrameSubTypes.ManagementBeacon, beaconFrame.FrameControl.SubType);
            Assert.IsFalse(beaconFrame.FrameControl.ToDS);
            Assert.IsFalse(beaconFrame.FrameControl.FromDS);
            Assert.IsFalse(beaconFrame.FrameControl.MoreFragments);
            Assert.IsFalse(beaconFrame.FrameControl.Retry);
            Assert.IsFalse(beaconFrame.FrameControl.PowerManagement);
            Assert.IsFalse(beaconFrame.FrameControl.MoreData);
            Assert.IsFalse(beaconFrame.FrameControl.Protected);
            Assert.IsFalse(beaconFrame.FrameControl.Order);
            Assert.AreEqual(0, beaconFrame.Duration.Field); //this need expanding on in the future
            Assert.AreEqual("FFFFFFFFFFFF", beaconFrame.DestinationAddress.ToString().ToUpper());
            Assert.AreEqual("0024B2F8D706", beaconFrame.SourceAddress.ToString().ToUpper());
            Assert.AreEqual("0024B2F8D706", beaconFrame.BssId.ToString().ToUpper());
            Assert.AreEqual(0, beaconFrame.SequenceControl.FragmentNumber);
            Assert.AreEqual(2892, beaconFrame.SequenceControl.SequenceNumber);
            Assert.AreEqual(0x000000A07A7BA566, beaconFrame.Timestamp);
            Assert.AreEqual(100, beaconFrame.BeaconInterval);
            Assert.IsTrue(beaconFrame.CapabilityInformation.IsEss);
            Assert.IsFalse(beaconFrame.CapabilityInformation.IsIbss);

            Assert.AreEqual(15, beaconFrame.InformationElements.Count);

            Assert.AreEqual(0x2BADAF43, beaconFrame.FrameCheckSequence);
            Assert.AreEqual(262, beaconFrame.FrameSize);
        }

        [Test]
        public void Test_ConstructorWithCorruptBuffer()
        {
            //buffer is way too short for frame. We are just checking it doesn't throw
            byte[] corruptBuffer = { 0x01 };
            var frame = new BeaconFrame(new ByteArraySegment(corruptBuffer));
            Assert.IsFalse(frame.FcsValid);
        }

        [Test]
        public void TestConstructWithValues()
        {
            var ssidInfoElement = new InformationElement(InformationElement.ElementId.ServiceSetIdentity, new byte[] { 0x68, 0x65, 0x6c, 0x6c, 0x6f });

            var frame = new BeaconFrame(
                                        PhysicalAddress.Parse("11-11-11-11-11-11"),
                                        PhysicalAddress.Parse("22-22-22-22-22-22"),
                                        new InformationElementList { ssidInfoElement })
            {
                FrameControl = { ToDS = true, Protected = true },
                Duration = { Field = 12345 },
                SequenceControl = { SequenceNumber = 3 },
                Timestamp = 123456789,
                BeaconInterval = 4444,
                CapabilityInformation = { IsIbss = true, Privacy = true }
            };

            frame.UpdateFrameCheckSequence();
            var fcs = frame.FrameCheckSequence;

            //serialize the frame into a byte buffer
            var bytes = frame.Bytes;
            var byteArraySegment = new ByteArraySegment(bytes);

            //create a new frame that should be identical to the original
            var recreatedFrame = MacFrame.ParsePacket(byteArraySegment) as BeaconFrame;
            recreatedFrame.UpdateFrameCheckSequence();

            Assert.AreEqual(FrameControlField.FrameSubTypes.ManagementBeacon, recreatedFrame.FrameControl.SubType);
            Assert.AreEqual(PhysicalAddress.Parse("11-11-11-11-11-11"), recreatedFrame.SourceAddress);
            Assert.AreEqual(PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), recreatedFrame.DestinationAddress);
            Assert.AreEqual(PhysicalAddress.Parse("22-22-22-22-22-22"), recreatedFrame.BssId);
            Assert.IsTrue(recreatedFrame.FrameControl.ToDS);
            Assert.IsTrue(recreatedFrame.FrameControl.Protected);
            Assert.AreEqual(12345, recreatedFrame.Duration.Field);
            Assert.AreEqual(3, recreatedFrame.SequenceControl.SequenceNumber);
            Assert.AreEqual(123456789, recreatedFrame.Timestamp);
            Assert.AreEqual(4444, recreatedFrame.BeaconInterval);
            Assert.AreEqual(ssidInfoElement, recreatedFrame.InformationElements[0]);

            Assert.AreEqual(fcs, recreatedFrame.FrameCheckSequence);
        }
    }
}