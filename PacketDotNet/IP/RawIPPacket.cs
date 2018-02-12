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
 *  Copyright 2010 Chris Morgan <chmorgan@gmail.com>
 *  Copyright 2016 Cameron Elliott <cameron@cameronelliott.com>
 */

using System;
using System.Collections.Generic;
using System.Text;
using PacketDotNet.Utils;

namespace PacketDotNet.IP
{
    /// <summary>
    ///     Raw IP packet
    ///     See http://www.tcpdump.org/linktypes.html look for LINKTYPE_RAW or DLT_RAW
    /// </summary>
    [Serializable]
    public class RawIPPacket : Packet
    {
        /// <summary>
        /// </summary>
        public RawIPPacketProtocol Protocol;

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="bas">
        ///     A <see cref="ByteArraySegment" />
        /// </param>
        public RawIPPacket(ByteArraySegment bas)
        {
            // Pcap raw link layer format does not have any header
            // you need to identify whether you have ipv4 or ipv6
            // directly by checking the IP version number.
            // If the first nibble is 0x04, then you have IP v4
            // If the first nibble is 0x06, then you have IP v6
            // The RawIPPacketProtocol enum has been defined to match this.
            var firstNibble = bas.Bytes[0] >> 4;
            this.Protocol = (RawIPPacketProtocol) firstNibble;

            this.HeaderByteArraySegment = new ByteArraySegment(bas)
            {
                Length = 0
            };

            // parse the encapsulated bytes
            this.PayloadPacketOrData = new PacketOrByteArraySegment();

            switch (this.Protocol)
            {
                case RawIPPacketProtocol.IPv4:
                    this.PayloadPacketOrData.ThePacket =
                        new IPv4Packet(this.HeaderByteArraySegment.EncapsulatedBytes());
                    break;
                case RawIPPacketProtocol.IPv6:
                    this.PayloadPacketOrData.ThePacket =
                        new IPv6Packet(this.HeaderByteArraySegment.EncapsulatedBytes());
                    break;
                default:
                    throw new NotImplementedException("Protocol of " + this.Protocol + " is not implemented");
            }
        }

        /// <summary> Fetch ascii escape sequence of the color associated with this packet type.</summary>
        public override String Color => AnsiEscapeSequences.DarkGray;

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
                    buffer.AppendFormat("{0}[RawPacket: Protocol={2}]{1}",
                        color,
                        colorEscape, this.Protocol);
                    break;
                case StringOutputType.Verbose:
                case StringOutputType.VerboseColored:
                    // collect the properties and their value
                    Dictionary<String, String> properties = new Dictionary<String, String>
                    {
                        {"protocol", this.Protocol + " (0x" + this.Protocol.ToString("x") + ")"}
                    };

                    // calculate the padding needed to right-justify the property names
                    Int32 padLength = RandomUtils.LongestStringLength(new List<String>(properties.Keys));

                    // build the output string
                    buffer.AppendLine("Raw:  ******* Raw - \"Raw IP Packet\" - offset=? length=" +
                                      this.TotalPacketLength);
                    buffer.AppendLine("Raw:");
                    foreach (var property in properties)
                    {
                        buffer.AppendLine("Raw: " + property.Key.PadLeft(padLength) + " = " + property.Value);
                    }

                    buffer.AppendLine("Raw:");
                    break;
            }

            // append the base output
            buffer.Append(base.ToString(outputFormat));

            return buffer.ToString();
        }
    }
}