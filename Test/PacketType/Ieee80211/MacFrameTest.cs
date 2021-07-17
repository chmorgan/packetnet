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
using PacketDotNet.Utils.Converters;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType.Ieee80211
{
    [TestFixture]
    public class MacFrameTest
    {
        /// <summary>
        /// Test that the MacFrame.FcsValid property is working correctly
        /// </summary>
        [Test]
        public void FCSTest()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "80211_association_request_frame.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            // check that the fcs can be calculated correctly
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
            var frame = (AssociationRequestFrame) p.PayloadPacket;
            Assert.AreEqual(0xde82c216, frame.FrameCheckSequence, "FCS mismatch");
            Assert.IsTrue(frame.FcsValid);

            // adjust the fcs of the packet and check that the FcsValid property returns false
            frame.FrameCheckSequence = 0x1;
            Assert.IsFalse(frame.FcsValid);
        }

        [Test]
        public void Test_AppendFcs_Raw80211WithFcs()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "80211_raw_with_fcs.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            //For this test we are just going to ignore the radio packet that precedes the data frame
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
            var macFrame = p as MacFrame;

            //When its raw 802.11 we cant tell if there is an FCS there so even though
            //there is we still expect AppendFcs to be false.
            Assert.IsFalse(macFrame.AppendFcs);
        }

        [Test]
        public void Test_AppendFcs_Raw80211WithoutFcs()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "80211_raw_without_fcs.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            //For this test we are just going to ignore the radio packet that precedes the data frame
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
            var macFrame = p as MacFrame;
            Assert.IsFalse(macFrame.AppendFcs);
        }

        [Test]
        public void Test_Bytes_ConstructedPacketWithFcsIncluded()
        {
            //We will use a DataDataFrame for this test but the 
            //type isn't really important.
            var dataFrame = new DataDataFrame
            {
                FrameControl = { FromDS = true },
                BssId = PhysicalAddress.Parse("AABBCCDDEEFF"),
                SourceAddress = PhysicalAddress.Parse("AABBCCDDEEFF"),
                DestinationAddress = PhysicalAddress.Parse("112233445566"),
                PayloadData = new byte[] { 0x1, 0x2, 0x3, 0x4 }
            };

            //Force it to recalculate the FCS and include it when serialized
            dataFrame.UpdateFrameCheckSequence();
            dataFrame.AppendFcs = true;
            Assert.IsTrue(dataFrame.FcsValid);

            var expectedLength = dataFrame.FrameSize + dataFrame.PayloadData.Length + 4;

            var frameBytes = dataFrame.Bytes;

            Assert.AreEqual(expectedLength, frameBytes.Length);
            Assert.AreEqual(dataFrame.FrameCheckSequence.ToString("X"),
                            EndianBitConverter.Big.ToUInt32(frameBytes, frameBytes.Length - 4).ToString("X"));

            Assert.AreEqual(dataFrame.FrameCheckSequence,
                            EndianBitConverter.Big.ToUInt32(frameBytes, frameBytes.Length - 4));
        }

        [Test]
        public void Test_Bytes_ConstructedPacketWithFcsNotIncluded()
        {
            //We will use a DataDataFrame for this test but the 
            //type isn't really important.
            var dataFrame = new DataDataFrame
            {
                FrameControl = { FromDS = true },
                BssId = PhysicalAddress.Parse("AABBCCDDEEFF"),
                SourceAddress = PhysicalAddress.Parse("AABBCCDDEEFF"),
                DestinationAddress = PhysicalAddress.Parse("112233445566"),
                PayloadData = new byte[] { 0x01, 0x02, 0x03, 0x04 }
            };

            //Force it to recalculate the FCS but don't include it when serialized
            dataFrame.UpdateFrameCheckSequence();
            dataFrame.AppendFcs = false;

            var expectedLength = dataFrame.FrameSize + dataFrame.PayloadData.Length;
            var frameBytes = dataFrame.Bytes;

            Assert.AreEqual(expectedLength, frameBytes.Length);
            //Check that we get last four bytes of data at the end rather than the FCS
            Assert.AreEqual(0x01020304, EndianBitConverter.Big.ToUInt32(frameBytes, frameBytes.Length - 4));
        }

        [Test]
        public void Test_Bytes_ParsedPacketWithFcsIncluded()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "80211_unencrypted_data_frame.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            //For this test we are just going to ignore the radio packet that precedes the data frame
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            var frame = (DataDataFrame) p.PayloadPacket;
            frame.AppendFcs = true;

            var frameBytes = frame.Bytes;
            var expectedLength = frame.FrameSize + frame.PayloadData.Length + 4;
            Assert.AreEqual(expectedLength, frameBytes.Length);
            Assert.AreEqual(frame.FrameCheckSequence,
                            EndianBitConverter.Big.ToUInt32(frameBytes, frameBytes.Length - 4));
        }

        [Test]
        public void Test_Bytes_ParsedPacketWithFcsNotIncluded()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "80211_unencrypted_data_frame.pcap");
            dev.Open();
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            dev.Close();

            //For this test we are just going to ignore the radio packet that precedes the data frame
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            var frame = (DataDataFrame) p.PayloadPacket;
            frame.AppendFcs = false;

            var frameBytes = frame.Bytes;
            var expectedLength = frame.FrameSize + frame.PayloadData.Length;
            Assert.AreEqual(expectedLength, frameBytes.Length);

            Assert.AreEqual(EndianBitConverter.Big.ToUInt32(frame.PayloadData, frame.PayloadData.Length - 4),
                            EndianBitConverter.Big.ToUInt32(frameBytes, frameBytes.Length - 4));
        }

        [Test]
        public void Test_NoFCS()
        {
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "80211_beacon_no_fcs.pcap");

            dev.Open();

            GetPacketStatus status;
            PacketCapture c;
            while ((status = dev.GetNextPacket(out c)) == GetPacketStatus.PacketRead)
            {
                var rawCapture = c.GetPacket();
                var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);
                Assert.IsNotNull(p.PayloadPacket);
            }

            // check that the fcs can be calculated correctly
            dev.Close();
        }
    }
}