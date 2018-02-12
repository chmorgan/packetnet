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
 *  Copyright 2009 Chris Morgan <chmorgan@gmail.com>
 *  Copyright 2010 Evan Plaice <evanplaice@gmail.com>
  */

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using PacketDotNet.IP;
using PacketDotNet.Udp;
using PacketDotNet.Utils;

namespace PacketDotNet.IGMP
{
    /// <summary>
    ///     An IGMP packet.
    /// </summary>
    [Serializable]
    public class IGMPv2Packet : InternetPacket
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="bas">
        ///     A <see cref="ByteArraySegment" />
        /// </param>
        public IGMPv2Packet(ByteArraySegment bas)
        {
            // set the header field, header field values are retrieved from this byte array
            this.HeaderByteArraySegment = new ByteArraySegment(bas)
            {
                Length = UdpFields.HeaderLength
            };

            // store the payload bytes
            this.PayloadPacketOrData = new PacketOrByteArraySegment
            {
                TheByteArraySegment = this.HeaderByteArraySegment.EncapsulatedBytes()
            };
        }

        /// <summary>
        ///     Constructor with parent
        /// </summary>
        /// <param name="bas">
        ///     A <see cref="ByteArraySegment" />
        /// </param>
        /// <param name="parentPacket">
        ///     A <see cref="Packet" />
        /// </param>
        public IGMPv2Packet(ByteArraySegment bas,
            Packet parentPacket) : this(bas)
        {
            this.ParentPacket = parentPacket;
        }

        /// <summary> Fetch ascii escape sequence of the color associated with this packet type.</summary>
        public override String Color => AnsiEscapeSequences.Brown;

        /// <summary> Fetch the IGMP header checksum.</summary>
        public virtual Int16 Checksum
        {
            get => BitConverter.ToInt16(this.HeaderByteArraySegment.Bytes,
                this.HeaderByteArraySegment.Offset + IGMPv2Fields.ChecksumPosition);

            set
            {
                Byte[] theValue = BitConverter.GetBytes(value);
                Array.Copy(theValue, 0, this.HeaderByteArraySegment.Bytes,
                    this.HeaderByteArraySegment.Offset + IGMPv2Fields.ChecksumPosition, 2);
            }
        }

        /// <summary> Fetch the IGMP group address.</summary>
        public virtual IPAddress GroupAddress => IpPacket.GetIPAddress(AddressFamily.InterNetwork,
            this.HeaderByteArraySegment.Offset + IGMPv2Fields.GroupAddressPosition, this.HeaderByteArraySegment.Bytes);

        /// <summary> Fetch the IGMP max response time.</summary>
        public virtual Byte MaxResponseTime
        {
            get => this.HeaderByteArraySegment.Bytes[
                this.HeaderByteArraySegment.Offset + IGMPv2Fields.MaxResponseTimePosition];

            set => this.HeaderByteArraySegment.Bytes[
                this.HeaderByteArraySegment.Offset + IGMPv2Fields.MaxResponseTimePosition] = value;
        }

        /// <value>
        ///     The type of IGMP message
        /// </value>
        public virtual IGMPMessageType Type
        {
            get => (IGMPMessageType) this.HeaderByteArraySegment.Bytes[
                this.HeaderByteArraySegment.Offset + IGMPv2Fields.TypePosition];

            set => this.HeaderByteArraySegment.Bytes[this.HeaderByteArraySegment.Offset + IGMPv2Fields.TypePosition] =
                (Byte) value;
        }

        /// <summary cref="Packet.ToString(StringOutputType)" />
        public override String ToString(StringOutputType outputFormat)
        {
            var buffer = new StringBuilder();
            String color = "";
            String colorEscape = "";

            if (outputFormat == StringOutputType.Colored || outputFormat == StringOutputType.VerboseColored)
            {
                color = this.Color;
                colorEscape = AnsiEscapeSequences.Reset;
            }

            switch (outputFormat)
            {
                case StringOutputType.Normal:
                case StringOutputType.Colored:
                    // build the output string
                    buffer.AppendFormat("{0}[IGMPv2Packet: Type={2}, MaxResponseTime={3}, GroupAddress={4}]{1}",
                        color,
                        colorEscape, this.Type,
                        String.Format("{0:0.0}", (this.MaxResponseTime / 10)), this.GroupAddress);
                    break;
                case StringOutputType.Verbose:
                case StringOutputType.VerboseColored:
                    // collect the properties and their value
                    Dictionary<String, String> properties = new Dictionary<String, String>
                    {
                        {"type", this.Type + " (0x" + this.Type.ToString("x") + ")"},
                        {
                            "max response time",
                            String.Format("{0:0.0}", this.MaxResponseTime / 10) + " sec (0x" +
                            this.MaxResponseTime.ToString("x") + ")"
                        },
                        // TODO: Implement checksum validation for IGMPv2
                        {"header checksum", "0x" + this.Checksum.ToString("x")},
                        {"group address", this.GroupAddress.ToString()}
                    };

                    // calculate the padding needed to right-justify the property names
                    Int32 padLength = RandomUtils.LongestStringLength(new List<String>(properties.Keys));

                    // build the output string
                    buffer.AppendLine(
                        "IGMP:  ******* IGMPv2 - \"Internet Group Management Protocol (Version 2)\" - offset=? length=" +
                        this.TotalPacketLength);
                    buffer.AppendLine("IGMP:");
                    foreach (var property in properties)
                    {
                        buffer.AppendLine("IGMP: " + property.Key.PadLeft(padLength) + " = " + property.Value);
                    }

                    buffer.AppendLine("IGMP:");
                    break;
            }

            // append the base string output
            buffer.Append(base.ToString(outputFormat));

            return buffer.ToString();
        }
    }
}