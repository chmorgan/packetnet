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
using System.Text;
using PacketDotNet.IP;
using PacketDotNet.MiscUtil.Utils;
using PacketDotNet.Udp;
using PacketDotNet.Utils;

namespace PacketDotNet.IGMP
{
    /// <summary>
    /// An IGMP packet.
    /// </summary>
    [Serializable]
    public class IGMPv2Packet : InternetPacket
    {
        /// <value>
        /// The type of IGMP message
        /// </value>
        virtual public IGMPMessageType Type
        {
            get
            {
                return (IGMPMessageType) this.header.Bytes[this.header.Offset + IGMPv2Fields.TypePosition];
            }

            set
            {
                this.header.Bytes[this.header.Offset + IGMPv2Fields.TypePosition] = (byte)value;
            }
        }

        /// <summary> Fetch the IGMP max response time.</summary>
        virtual public byte MaxResponseTime
        {
            get
            {
                return this.header.Bytes[this.header.Offset + IGMPv2Fields.MaxResponseTimePosition];
            }

            set
            {
                this.header.Bytes[this.header.Offset + IGMPv2Fields.MaxResponseTimePosition] = value;
            }
        }

        /// <summary> Fetch the IGMP header checksum.</summary>
        virtual public short Checksum
        {
            get
            {
                return BitConverter.ToInt16(this.header.Bytes, this.header.Offset + IGMPv2Fields.ChecksumPosition);
            }

            set
            {
                byte[] theValue = BitConverter.GetBytes(value);
                Array.Copy((Array) theValue, (int) 0, (Array) this.header.Bytes, (int) (this.header.Offset + IGMPv2Fields.ChecksumPosition), 2);
            }
        }

        /// <summary> Fetch the IGMP group address.</summary>
        virtual public System.Net.IPAddress GroupAddress
        {
            get
            {
                return IpPacket.GetIPAddress(System.Net.Sockets.AddressFamily.InterNetwork, this.header.Offset + IGMPv2Fields.GroupAddressPosition, this.header.Bytes);
            }

        }

        /// <summary> Fetch ascii escape sequence of the color associated with this packet type.</summary>
        override public String Color
        {
            get
            {
                return AnsiEscapeSequences.Brown;
            }

        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="bas">
        /// A <see cref="ByteArraySegment"/>
        /// </param>
        public IGMPv2Packet(ByteArraySegment bas)
        {
            // set the header field, header field values are retrieved from this byte array
            this.header = new ByteArraySegment(bas)
            {
                Length = UdpFields.HeaderLength
            };

            // store the payload bytes
            this.payloadPacketOrData = new PacketOrByteArraySegment
            {
                TheByteArraySegment = this.header.EncapsulatedBytes()
            };
        }

        /// <summary>
        /// Constructor with parent
        /// </summary>
        /// <param name="bas">
        /// A <see cref="ByteArraySegment"/>
        /// </param>
        /// <param name="ParentPacket">
        /// A <see cref="Packet"/>
        /// </param>
        public IGMPv2Packet(ByteArraySegment bas,
                            Packet ParentPacket) : this(bas)
        {
            this.ParentPacket = ParentPacket;
        }

        /// <summary cref="Packet.ToString(StringOutputType)" />
        public override string ToString(StringOutputType outputFormat)
        {
            var buffer = new StringBuilder();
            string color = "";
            string colorEscape = "";

            if(outputFormat == StringOutputType.Colored || outputFormat == StringOutputType.VerboseColored)
            {
                color = this.Color;
                colorEscape = AnsiEscapeSequences.Reset;
            }

            if(outputFormat == StringOutputType.Normal || outputFormat == StringOutputType.Colored)
            {
                // build the output string
                buffer.AppendFormat("{0}[IGMPv2Packet: Type={2}, MaxResponseTime={3}, GroupAddress={4}]{1}",
                    color,
                    colorEscape, this.Type,
                    String.Format("{0:0.0}", (this.MaxResponseTime / 10)), this.GroupAddress);
            }

            if(outputFormat == StringOutputType.Verbose || outputFormat == StringOutputType.VerboseColored)
            {
                // collect the properties and their value
                Dictionary<string,string> properties = new Dictionary<string,string>();
                properties.Add("type", this.Type + " (0x" + this.Type.ToString("x") + ")");
                properties.Add("max response time", String.Format("{0:0.0}", this.MaxResponseTime / 10) + " sec (0x" + this.MaxResponseTime.ToString("x") + ")");
                // TODO: Implement checksum validation for IGMPv2
                properties.Add("header checksum", "0x" + this.Checksum.ToString("x"));
                properties.Add("group address", this.GroupAddress.ToString());

                // calculate the padding needed to right-justify the property names
                int padLength = RandomUtils.LongestStringLength(new List<string>(properties.Keys));

                // build the output string
                buffer.AppendLine("IGMP:  ******* IGMPv2 - \"Internet Group Management Protocol (Version 2)\" - offset=? length=" + this.TotalPacketLength);
                buffer.AppendLine("IGMP:");
                foreach (var property in properties)
                {
                    buffer.AppendLine("IGMP: " + property.Key.PadLeft(padLength) + " = " + property.Value);
                }
                buffer.AppendLine("IGMP:");
            }

            // append the base string output
            buffer.Append((string) base.ToString(outputFormat));

            return buffer.ToString();
        }
    }
}
