/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using PacketDotNet.Utils;
using PacketDotNet.Utils.Converters;

#if DEBUG
using log4net;
using System.Reflection;
#endif

namespace PacketDotNet
{
    /// <summary>
    /// An ICMP packet
    /// See http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    /// </summary>
    public sealed class IcmpV4Packet : InternetPacket
    {
#if DEBUG
        private static readonly ILog Log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
#else
// NOTE: No need to warn about lack of use, the compiler won't
//       put any calls to 'log' here but we need 'log' to exist to compile
#pragma warning disable 0169, 0649
        private static readonly ILogInactive Log;
#pragma warning restore 0169, 0649
#endif

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="byteArraySegment">
        /// A <see cref="ByteArraySegment" />
        /// </param>
        public IcmpV4Packet(ByteArraySegment byteArraySegment)
        {
            Log.Debug("");

            // ReSharper disable once UseObjectOrCollectionInitializer
            Header = new ByteArraySegment(byteArraySegment);
            Header.Length = IcmpV4Fields.HeaderLength;

            // store the payload bytes
            PayloadPacketOrData = new LazySlim<PacketOrByteArraySegment>(() => new PacketOrByteArraySegment { ByteArraySegment = Header.NextSegment() });
        }

        /// <summary>
        /// Construct with parent packet
        /// </summary>
        /// <param name="byteArraySegment">
        /// A <see cref="ByteArraySegment" />
        /// </param>
        /// <param name="parentPacket">
        /// A <see cref="Packet" />
        /// </param>
        public IcmpV4Packet
        (
            ByteArraySegment byteArraySegment,
            Packet parentPacket) : this(byteArraySegment)
        {
            ParentPacket = parentPacket;
        }

        /// <value>
        /// Checksum value
        /// </value>
        public ushort Checksum
        {
            get => EndianBitConverter.Big.ToUInt16(Header.Bytes,
                                                   Header.Offset + IcmpV4Fields.ChecksumPosition);
            set
            {
                var v = value;
                EndianBitConverter.Big.CopyBytes(v,
                                                 Header.Bytes,
                                                 Header.Offset + IcmpV4Fields.ChecksumPosition);
            }
        }

        /// <summary>Fetch ascii escape sequence of the color associated with this packet type.</summary>
        public override string Color => AnsiEscapeSequences.LightBlue;

        /// <summary>
        /// Contents of the ICMP packet
        /// </summary>
        public byte[] Data
        {
            get => PayloadPacketOrData.Value.ByteArraySegment.ActualBytes();
            set => PayloadPacketOrData.Value.ByteArraySegment = new ByteArraySegment(value, 0, value.Length);
        }

        /// <summary>
        /// Gets or sets the identifier field.
        /// </summary>
        public ushort Id
        {
            get => EndianBitConverter.Big.ToUInt16(Header.Bytes,
                                                   Header.Offset + IcmpV4Fields.IdPosition);
            set
            {
                var v = value;
                EndianBitConverter.Big.CopyBytes(v,
                                                 Header.Bytes,
                                                 Header.Offset + IcmpV4Fields.IdPosition);
            }
        }

        /// <summary>
        /// Sequence field
        /// </summary>
        public ushort Sequence
        {
            get => EndianBitConverter.Big.ToUInt16(Header.Bytes,
                                                   Header.Offset + IcmpV4Fields.SequencePosition);
            set => EndianBitConverter.Big.CopyBytes(value,
                                                    Header.Bytes,
                                                    Header.Offset + IcmpV4Fields.SequencePosition);
        }

        /// <value>
        /// The Type/Code enum value
        /// </value>
        public IcmpV4TypeCode TypeCode
        {
            get
            {
                var val = EndianBitConverter.Big.ToUInt16(Header.Bytes,
                                                          Header.Offset + IcmpV4Fields.TypeCodePosition);

                return (IcmpV4TypeCode) val;
            }
            set
            {
                var v = (ushort) value;
                EndianBitConverter.Big.CopyBytes(v,
                                                 Header.Bytes,
                                                 Header.Offset + IcmpV4Fields.TypeCodePosition);
            }
        }

        /// <summary>Check if the ICMP packet is valid, checksum-wise.</summary>
        public bool ValidChecksum => ValidIcmpChecksum;

        /// <summary>
        /// Check if the ICMP packet is valid, checksum-wise.
        /// </summary>
        public bool ValidIcmpChecksum
        {
            get
            {
                Log.Debug("");

                var calculatedChecksum = CalculateIcmpChecksum();

                Log.DebugFormat(HexPrinter.GetString(Bytes, 0, Bytes.Length));

                var result = Checksum == calculatedChecksum;

                Log.DebugFormat("calculatedChecksum: {0}, Checksum {1}, returning {2}", calculatedChecksum, Checksum, result);

                return result;
            }
        }

        /// <summary>
        /// Calculates the ICMP checksum.
        /// </summary>
        /// <returns>The calculated ICMP checksum.</returns>
        public ushort CalculateIcmpChecksum()
        {
            var originalChecksum = Checksum;

            Checksum = 0; // This needs to be reset first to calculate the checksum.

            var calculatedChecksum = ChecksumUtils.OnesComplementSum(Bytes, 0, Bytes.Length);

            Checksum = originalChecksum;

            return (ushort)calculatedChecksum;
        }

        /// <summary>
        /// Update the checksum value.
        /// </summary>
        public void UpdateIcmpChecksum()
        {
            Checksum = CalculateIcmpChecksum();
        }

        /// <summary cref="Packet.ToString(StringOutputType)" />
        public override string ToString(StringOutputType outputFormat)
        {
            var buffer = new StringBuilder();
            var color = "";
            var colorEscape = "";

            if (outputFormat == StringOutputType.Colored || outputFormat == StringOutputType.VerboseColored)
            {
                color = Color;
                colorEscape = AnsiEscapeSequences.Reset;
            }

            switch (outputFormat)
            {
                case StringOutputType.Normal:
                case StringOutputType.Colored:
                {
                    // build the output string
                    buffer.AppendFormat("{0}[IcmpV4Packet: TypeCode={2}]{1}",
                                        color,
                                        colorEscape,
                                        TypeCode);

                    break;
                }
                case StringOutputType.Verbose:
                case StringOutputType.VerboseColored:
                {
                    // collect the properties and their value
                    var properties = new Dictionary<string, string>
                    {
                        { "type/code", TypeCode + " (0x" + TypeCode.ToString("x") + ")" },
                        // TODO: Implement checksum verification for ICMPv4
                        { "checksum", Checksum.ToString("x") },
                        { "identifier", "0x" + Id.ToString("x") },
                        { "sequence number", Sequence + " (0x" + Sequence.ToString("x") + ")" }
                    };

                    // calculate the padding needed to right-justify the property names
                    var padLength = RandomUtils.LongestStringLength(new List<string>(properties.Keys));

                    // build the output string
                    buffer.AppendLine("ICMP:  ******* ICMPv4 - \"Internet Control Message Protocol (Version 4)\" - offset=? length=" + TotalPacketLength);
                    buffer.AppendLine("ICMP:");
                    foreach (var property in properties)
                    {
                        buffer.AppendLine("ICMP: " + property.Key.PadLeft(padLength) + " = " + property.Value);
                    }

                    buffer.AppendLine("ICMP:");
                    break;
                }
            }

            // append the base string output
            buffer.Append(base.ToString(outputFormat));

            return buffer.ToString();
        }
    }
}