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
 */

using System;
using System.Collections.Generic;
using System.Text;
using PacketDotNet.IP;
using PacketDotNet.MiscUtil.Utils;
using PacketDotNet.Utils;
using PacketDotNet.Utils.Conversion;

namespace PacketDotNet.ICMP
{
    /// <summary>
    /// An ICMP packet
    /// See http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    /// </summary>
    [Serializable]
    public class ICMPv4Packet : InternetPacket
    {
#if DEBUG
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
#else
        // NOTE: No need to warn about lack of use, the compiler won't
        //       put any calls to 'log' here but we need 'log' to exist to compile
#pragma warning disable 0169, 0649
        private static readonly ILogInactive log;
#pragma warning restore 0169, 0649
#endif

        /// <value>
        /// The Type/Code enum value
        /// </value>
        virtual public ICMPv4TypeCodes TypeCode
        {
            get
            {
                var val = EndianBitConverter.Big.ToUInt16(this.header.Bytes, this.header.Offset + ICMPv4Fields.TypeCodePosition);

                //TODO: how to handle a mismatch in the mapping? maybe throw here?
                if(Enum.IsDefined(typeof(ICMPv4TypeCodes), val))
                    return (ICMPv4TypeCodes)val;
                else
                    throw new NotImplementedException("TypeCode of " + val + " is not defined in ICMPv4TypeCode");
            }

            set
            {
                var theValue = (UInt16)value;
                EndianBitConverter.Big.CopyBytes(theValue, this.header.Bytes, this.header.Offset + ICMPv4Fields.TypeCodePosition);
            }
        }

        /// <value>
        /// Checksum value
        /// </value>
        public ushort Checksum
        {
            get
            {
                return EndianBitConverter.Big.ToUInt16(this.header.Bytes, this.header.Offset + ICMPv4Fields.ChecksumPosition);
            }

            set
            {
                var theValue = value;
                EndianBitConverter.Big.CopyBytes(theValue, this.header.Bytes, this.header.Offset + ICMPv4Fields.ChecksumPosition);
            }
        }

        /// <summary>
        /// ID field
        /// </summary>
        public ushort ID
        {
            get
            {
                return EndianBitConverter.Big.ToUInt16(this.header.Bytes, this.header.Offset + ICMPv4Fields.IDPosition);
            }

            set
            {
                var theValue = value;
                EndianBitConverter.Big.CopyBytes(theValue, this.header.Bytes, this.header.Offset + ICMPv4Fields.IDPosition);
            }
        }

        /// <summary>
        /// Sequence field
        /// </summary>
        public ushort Sequence
        {
            get
            {
                return EndianBitConverter.Big.ToUInt16(this.header.Bytes, this.header.Offset + ICMPv4Fields.SequencePosition);
            }

            set
            {
                EndianBitConverter.Big.CopyBytes(value, this.header.Bytes, this.header.Offset + ICMPv4Fields.SequencePosition);
            }
        }

        /// <summary>
        /// Contents of the ICMP packet
        /// </summary>
        public byte[] Data
        {
            get
            {
                return this.payloadPacketOrData.TheByteArraySegment.ActualBytes();
            }

            set
            {
                this.payloadPacketOrData.TheByteArraySegment = new ByteArraySegment(value, 0, value.Length);
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="bas">
        /// A <see cref="ByteArraySegment"/>
        /// </param>
        public ICMPv4Packet(ByteArraySegment bas)
        {
            log.Debug("");

            this.header = new ByteArraySegment(bas)
            {
                Length = ICMPv4Fields.HeaderLength
            };

            // store the payload bytes
            this.payloadPacketOrData = new PacketOrByteArraySegment
            {
                TheByteArraySegment = this.header.EncapsulatedBytes()
            };
        }

        /// <summary>
        /// Construct with parent packet
        /// </summary>
        /// <param name="bas">
        /// A <see cref="ByteArraySegment"/>
        /// </param>
        /// <param name="ParentPacket">
        /// A <see cref="Packet"/>
        /// </param>
        public ICMPv4Packet(ByteArraySegment bas,
                            Packet ParentPacket) : this(bas)
        {
            this.ParentPacket = ParentPacket;
        }

        /// <summary> Fetch ascii escape sequence of the color associated with this packet type.</summary>
        override public String Color
        {
            get
            {
                return AnsiEscapeSequences.LightBlue;
            }
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
                buffer.AppendFormat("{0}[ICMPPacket: TypeCode={2}]{1}",
                    color,
                    colorEscape, this.TypeCode);
            }

            if(outputFormat == StringOutputType.Verbose || outputFormat == StringOutputType.VerboseColored)
            {
                // collect the properties and their value
                Dictionary<string,string> properties = new Dictionary<string,string>();
                properties.Add("type/code", this.TypeCode.ToString() + " (0x" + this.TypeCode.ToString("x") + ")");
                // TODO: Implement checksum verification for ICMPv4
                properties.Add("checksum", this.Checksum.ToString("x"));
                properties.Add("identifier", "0x" + this.ID.ToString("x"));
                properties.Add("sequence number", this.Sequence + " (0x" + this.Sequence.ToString("x") + ")");

                // calculate the padding needed to right-justify the property names
                int padLength = RandomUtils.LongestStringLength(new List<string>(properties.Keys));

                // build the output string
                buffer.AppendLine("ICMP:  ******* ICMPv4 - \"Internet Control Message Protocol (Version 4)\" - offset=? length=" + this.TotalPacketLength);
                buffer.AppendLine("ICMP:");
                foreach (var property in properties)
                {
                    buffer.AppendLine("ICMP: " + property.Key.PadLeft(padLength) + " = " + property.Value);
                }
                buffer.AppendLine("ICMP:");
                }

            // append the base string output
            buffer.Append((string) base.ToString(outputFormat));

            return buffer.ToString();
        }
    }
}
