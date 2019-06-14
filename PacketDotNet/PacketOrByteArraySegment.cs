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
 * Copyright 2010 Chris Morgan <chmorgan@gmail.com>
 */

using System.Text;
using System.IO;
using PacketDotNet.Utils;

namespace PacketDotNet
{
    /// <summary>
    /// Encapsulates and ensures that we have either a Packet OR a ByteArraySegment, but not both.
    /// </summary>
    public sealed class PacketOrByteArraySegment
    {
        private ByteArraySegment _byteArraySegment;

        private Packet _packet;

        /// <summary>
        /// Gets or sets the byte array segment.
        /// </summary>
        public ByteArraySegment ByteArraySegment
        {
            get => _byteArraySegment;
            set
            {
                _packet = null;
                _byteArraySegment = value;
            }
        }

        /// <summary>
        /// Gets or sets the packet.
        /// </summary>
        public Packet Packet
        {
            get => _packet;
            set
            {
                _byteArraySegment = null;
                _packet = value;
            }
        }

        /// <value>
        /// Whether or not this container contains a packet, a byte[] or neither.
        /// </value>
        public PayloadType Type
        {
            get
            {
                if (Packet != null)
                    return PayloadType.Packet;


                return ByteArraySegment != null ? PayloadType.Bytes : PayloadType.None;
            }
        }

        /// <summary>
        /// Appends either the byte array or the packet, if non-null, to the <see cref="MemoryStream" />.
        /// </summary>
        /// <param name="memoryStream">
        /// A <see cref="MemoryStream" />
        /// </param>
        public void AppendToMemoryStream(MemoryStream memoryStream)
        {
            if (Packet != null)
            {
                var bytes = Packet.Bytes;
                memoryStream.Write(bytes, 0, bytes.Length);
            }
            else if (ByteArraySegment != null)
            {
                foreach (var b in ByteArraySegment)
                    memoryStream.WriteByte(b);
            }
        }

        public override string ToString()
        {
            var buffer = new StringBuilder();
            if (Type == PayloadType.Bytes)
            {
                buffer.AppendFormat("ByteArraySegment: [" + ByteArraySegment + "]");
            } else
            {
                buffer.AppendFormat("Packet: [" + Packet + "]");
            }

            return buffer.ToString();
        }
    }
}