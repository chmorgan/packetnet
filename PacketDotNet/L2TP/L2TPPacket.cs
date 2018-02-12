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
 *  Copyright 2018 Steven Haufe<haufes@hotmail.com>
  */

using System;
using System.Text;
using PacketDotNet.PPP;
using PacketDotNet.Utils;
using PacketDotNet.Utils.Conversion;

namespace PacketDotNet.L2TP
{
    /// <summary>
    ///     An L2TP packet.
    /// </summary>
    [Serializable]
    public class L2TPPacket : Packet
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="bas">
        ///     A <see cref="ByteArraySegment" />
        /// </param>
        public L2TPPacket(ByteArraySegment bas, Packet parentPacket)
        {
            // slice off the header portion
            this.HeaderByteArraySegment = new ByteArraySegment(bas)
            {
                Length = L2TPFields.HeaderLength
            };
            if (this.HasLength) this.HeaderByteArraySegment.Length += L2TPFields.LengthsLength;
            if (this.HasSequence) this.HeaderByteArraySegment.Length += L2TPFields.NsLength + L2TPFields.NrLength;
            if (this.HasOffset)
                this.HeaderByteArraySegment.Length += L2TPFields.OffsetSizeLength + L2TPFields.OffsetPadLength;

            var payload = this.HeaderByteArraySegment.EncapsulatedBytes();
            try
            {
                this.PayloadPacket = new PPPPacket(payload)
                {
                    ParentPacket = this
                };
            }
            catch (Exception)
            {
                //it's not a PPP packet, just attach the data
                this.PayloadPacketOrData.TheByteArraySegment = payload;
            }

            this.ParentPacket = parentPacket;
        }

        /// <summary> Fetch ascii escape sequence of the color associated with this packet type.</summary>
        public override String Color => AnsiEscapeSequences.DarkGray;

        public virtual Boolean DataMessage =>
            8 == (this.HeaderByteArraySegment.Bytes[this.HeaderByteArraySegment.Offset] & 0x8);

        public virtual Boolean HasLength =>
            4 == (this.HeaderByteArraySegment.Bytes[this.HeaderByteArraySegment.Offset] & 0x4);

        public virtual Boolean HasOffset =>
            2 == (this.HeaderByteArraySegment.Bytes[this.HeaderByteArraySegment.Offset] & 0x2);

        public virtual Boolean HasSequence =>
            2 == (this.HeaderByteArraySegment.Bytes[this.HeaderByteArraySegment.Offset] & 0x2);

        public virtual Boolean IsPriority =>
            2 == (this.HeaderByteArraySegment.Bytes[this.HeaderByteArraySegment.Offset] & 0x2);

        public virtual Int32 SessionID
        {
            get
            {
                if (this.HasLength)
                    return EndianBitConverter.Big.ToUInt16(this.HeaderByteArraySegment.Bytes,
                        this.HeaderByteArraySegment.Offset + 5);
                return EndianBitConverter.Big.ToUInt16(this.HeaderByteArraySegment.Bytes,
                    this.HeaderByteArraySegment.Offset + 4);
            }
        }

        public virtual Int32 TunnelID
        {
            get
            {
                if (this.HasLength)
                    return EndianBitConverter.Big.ToUInt16(this.HeaderByteArraySegment.Bytes,
                        this.HeaderByteArraySegment.Offset + 3);
                return EndianBitConverter.Big.ToUInt16(this.HeaderByteArraySegment.Bytes,
                    this.HeaderByteArraySegment.Offset + 2);
            }
        }

        public virtual Int32 Version =>
            (this.HeaderByteArraySegment.Bytes[this.HeaderByteArraySegment.Offset + 1] & 0x7);


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

            if (outputFormat == StringOutputType.Normal || outputFormat == StringOutputType.Colored)
            {
                // build the output string
                buffer.AppendFormat("{0}[L2TPPacket",
                    color,
                    colorEscape);
            }


            // append the base string output
            buffer.Append(base.ToString(outputFormat));

            return buffer.ToString();
        }
    }
}