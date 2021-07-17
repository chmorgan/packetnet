/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

using System;
using System.Collections.Generic;
using log4net.Core;
using NUnit.Framework;
using PacketDotNet;
using SharpPcap;

namespace Test.Misc
{
    /// <summary>
    /// Unit test that tries to exercise the string output methods in all of the
    /// packet classes to make it easier to identify and fix printing issues
    /// </summary>
    [TestFixture]
    public class StringOutputTest
    {
        private static readonly log4net.ILog Log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        private class FileAndPacketIndexes
        {
            public readonly string Filename;
            public readonly List<string> PacketDescription;
            public readonly List<int> PacketIndexes;

            public FileAndPacketIndexes
            (
                string filename,
                List<int> packetIndexes,
                List<string> packetDescription)
            {
                Filename = filename;
                PacketIndexes = packetIndexes;
                PacketDescription = packetDescription;
            }
        }

        private static readonly List<FileAndPacketIndexes> FilePacketIndexes;

        static StringOutputTest()
        {
            FilePacketIndexes = new List<FileAndPacketIndexes>();

            /*
             * TODO:
             * Need to add packets of these types:
             * igmpv2
             */

            /////////////////////////
            // setup an array of file names and packet indexes

            // ethernet arp request and response
            FilePacketIndexes.Add(new FileAndPacketIndexes(NUnitSetupClass.CaptureDirectory + "arp_request_response.pcap",
                                                           new List<int>(new[] { 0, 1 }),
                                                           new List<string>(new[]
                                                           {
                                                               "ethernet arp request",
                                                               "ethernet arp response"
                                                           })));

            // linux cooked capture, ipv4, tcp
            FilePacketIndexes.Add(new FileAndPacketIndexes(NUnitSetupClass.CaptureDirectory + "LinuxCookedCapture.pcap",
                                                           new List<int>(new[] { 2 }),
                                                           new List<string>(new[] { "linux cooked capture, ipv4, tcp" })));

            // ethernet, ipv6, icmpv6
            FilePacketIndexes.Add(new FileAndPacketIndexes(NUnitSetupClass.CaptureDirectory + "ipv6_icmpv6_packet.pcap",
                                                           new List<int>(new[] { 0 }),
                                                           new List<string>(new[] { "ethernet, ipv6, icmpv6" })));

            // ethernet, PPPoE, PPP, ipv4, udp
            FilePacketIndexes.Add(new FileAndPacketIndexes(NUnitSetupClass.CaptureDirectory + "PPPoEPPP.pcap",
                                                           new List<int>(new[] { 1 }),
                                                           new List<string>(new[] { "ethernet, PPPoE, PPP, ipv4, udp" })));

            ExpectedTotalPackets = 5;
        }

        private static int _fileAndPacketIndex;

        /// <summary>
        /// Index into FileAndPacketIndexes.PacketIndex
        /// </summary>
        private static int _currentPacketIndex;

        private static string _currentPacketDescription;

        private static string _packetFileName;
        private static int _indexIntoPacketFile;

        private static FileAndPacketIndexes _currentFapi;

        private static SharpPcap.LibPcap.CaptureFileReaderDevice _captureFileReader;

        private static int _totalPacketsReturned;
        private static readonly int ExpectedTotalPackets;

        private static Packet GetNextPacket()
        {
            if (_currentFapi != null)
            {
                Log.DebugFormat("currentFAPI.PacketIndexes.Count {0}," +
                                "currentPacketIndex {1}",
                                _currentFapi.PacketIndexes.Count,
                                _currentPacketIndex);
            }
            else
            {
                Log.Debug("currentFAPI is null");
            }

            // do we need to open a file up or are we done with the current file?
            if ((_packetFileName == null) ||
                (_currentFapi == null) ||
                (_currentFapi.PacketIndexes.Count == _currentPacketIndex))
            {
                Log.Debug("opening a new file up");

                // close the open device if there was one
                if (_captureFileReader != null)
                {
                    _captureFileReader.Close();
                    _captureFileReader = null;
                }

                // do we have any more files to process?
                if (_fileAndPacketIndex >= FilePacketIndexes.Count)
                {
                    Log.DebugFormat("totalPacketsReturned {0}, expectedTotalPackets {1}",
                                    _totalPacketsReturned,
                                    ExpectedTotalPackets);

                    Assert.AreEqual(ExpectedTotalPackets,
                                    _totalPacketsReturned,
                                    "expectedTotalPackets does not match totalPacketsReturned");

                    return null;
                }

                _currentFapi = FilePacketIndexes[_fileAndPacketIndex];
                _currentPacketIndex = 0;
                _packetFileName = _currentFapi.Filename;

                // opening a new file, we are at the first index into the new file
                _indexIntoPacketFile = 0;

                try
                {
                    Log.DebugFormat("Opening {0}", _currentFapi.Filename);

                    _captureFileReader = new SharpPcap.LibPcap.CaptureFileReaderDevice(_currentFapi.Filename);
                    _captureFileReader.Open();

                    _fileAndPacketIndex++;
                }
                catch (Exception e)
                {
                    Log.Error("caught exception", e);
                    throw;
                }
            }

            Packet p;

            do
            {
                Log.DebugFormat("currentPacketIndex {0}", _currentPacketIndex);
                Log.DebugFormat("indexIntoPacketFile {0}, currentFAPI.PacketIndexes[currentPacketIndex] {1}",
                                _indexIntoPacketFile,
                                _currentFapi.PacketIndexes[_currentPacketIndex]);

                Log.Debug("retrieving packet");

                // read the next packet
                PacketCapture c;
                _captureFileReader.GetNextPacket(out c);
                var packet = c.GetPacket();
                Assert.IsNotNull(packet, "Expected a valid packet but it was null");
                
                p = Packet.ParsePacket(packet.GetLinkLayers(), packet.Data);

                _currentPacketDescription = _currentFapi.PacketDescription[_currentPacketIndex];

                // advance our index into the current packet file
                _indexIntoPacketFile++;
            }
            while ((_indexIntoPacketFile - 1) != _currentFapi.PacketIndexes[_currentPacketIndex]);
            // does the current index match the index of the packet we want?

            // and because we got a packet we advance our index into the FileAndPacketIndex class
            _currentPacketIndex++;

            Log.Debug("returning packet");
            _totalPacketsReturned++;
            return p;
        }

        private void ResetPacketPosition()
        {
            _fileAndPacketIndex = 0;
            _currentPacketIndex = 0;
            _packetFileName = null;

            _indexIntoPacketFile = 0;

            _totalPacketsReturned = 0;

            if (_captureFileReader != null)
            {
                _captureFileReader.Close();
                _captureFileReader = null;
            }
        }

        private void OutputPacket(Packet p, StringOutputType outputType)
        {
            Console.WriteLine(_currentPacketDescription + " - " + outputType);
            Console.Write(p.ToString(outputType));
            if (outputType == StringOutputType.Verbose || outputType == StringOutputType.VerboseColored)
                Console.Write(p.PrintHex());

            Console.WriteLine();
        }

        [Test]
        public void _ToString()
        {
            ResetPacketPosition();

            // store the logging value
            var oldThreshold = LoggingConfiguration.GlobalLoggingLevel;

            // disable logging to reduce console output
            LoggingConfiguration.GlobalLoggingLevel = Level.Off;

            Packet p;
            while ((p = GetNextPacket()) != null)
            {
                OutputPacket(p, StringOutputType.Normal);
            }

            LoggingConfiguration.GlobalLoggingLevel = oldThreshold;
        }

        [Test]
        public void ToColoredString()
        {
            ResetPacketPosition();

            // store the logging value
            var oldThreshold = LoggingConfiguration.GlobalLoggingLevel;

            // disable logging to reduce console output
            LoggingConfiguration.GlobalLoggingLevel = Level.Off;

            Packet p;
            while ((p = GetNextPacket()) != null)
            {
                OutputPacket(p, StringOutputType.Colored);
            }

            LoggingConfiguration.GlobalLoggingLevel = oldThreshold;
        }

        [Test]
        public void ToColoredVerboseString()
        {
            ResetPacketPosition();

            // store the logging value
            var oldThreshold = LoggingConfiguration.GlobalLoggingLevel;

            // disable logging to reduce console output
            LoggingConfiguration.GlobalLoggingLevel = Level.Off;

            Packet p;
            while ((p = GetNextPacket()) != null)
            {
                OutputPacket(p, StringOutputType.VerboseColored);
            }

            LoggingConfiguration.GlobalLoggingLevel = oldThreshold;
        }

        [Test]
        public void ToVerboseString()
        {
            ResetPacketPosition();

            // store the logging value
            var oldThreshold = LoggingConfiguration.GlobalLoggingLevel;

            // disable logging to reduce console output
            LoggingConfiguration.GlobalLoggingLevel = Level.Off;

            Packet p;
            while ((p = GetNextPacket()) != null)
            {
                OutputPacket(p, StringOutputType.Verbose);
            }

            LoggingConfiguration.GlobalLoggingLevel = oldThreshold;
        }
    }
}