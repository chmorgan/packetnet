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
 *  Copyright 2010 Evan Plaice <evanplaice@gmail.com>
 *  Copyright 2010 Chris Morgan <chmorgan@gmail.com>
 */

using System;
using PacketDotNet.Utils;

#if DEBUG
using log4net;
using System.Reflection;
#endif

namespace PacketDotNet.Lldp
{
    /// <summary>
    /// A Type-Length-Value object
    /// </summary>
    public class Tlv
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

        private ByteArraySegment _data;

        /// <summary>
        /// Create a tlv
        /// </summary>
        public Tlv()
        { }

        /// <summary>
        /// Creates a Tlv
        /// </summary>
        /// <param name="bytes">
        /// Bytes that comprise the Tlv
        /// </param>
        /// <param name="offset">
        /// The TLVs offset from the start of byte[] bytes
        /// </param>
        public Tlv(byte[] bytes, int offset)
        {
            // setup a local ByteArrayAndOffset in order to retrieve the value length
            // NOTE: we cannot set tlvData to retrieve the value length as
            //       setting tlvData results in the TypeLength.Length being updated with
            //       the length of the ByteArrayAndOffset which would overwrite the value
            //       we are trying to retrieve
            var byteArraySegment = new ByteArraySegment(bytes, offset, TlvTypeLength.TypeLengthLength);
            TypeLength = new TlvTypeLength(byteArraySegment);

            // set the tlvData assuming we have at least the bytes required for the
            // type/length fields
            Data = new ByteArraySegment(bytes, offset, TypeLength.Length + TlvTypeLength.TypeLengthLength)
            {
                Length = TypeLength.Length + TlvTypeLength.TypeLengthLength
            };
        }

        /// <summary>
        /// Length of value portion of the Tlv
        /// NOTE: Does not include the length of the Type and Length fields
        /// </summary>
        public int Length
        {
            get => TypeLength.Length;

            // Length set property is internal because the TLV length is
            // automatically set based on the length of the TLV value
            internal set => TypeLength.Length = value;
        }

        /// <summary>
        /// Total length of the Tlv, including the length of the Type and Length fields
        /// </summary>
        public int TotalLength => Data.Length;

        /// <summary>
        /// TLV type
        /// </summary>
        public TlvType Type
        {
            get => TypeLength.Type;
            set
            {
                Log.DebugFormat("value {0}", value);
                TypeLength.Type = value;
            }
        }

        /// <summary>
        /// Offset to the value bytes of the Tlv
        /// </summary>
        internal int ValueOffset => Data.Offset + TlvTypeLength.TypeLengthLength;

        /// <summary>
        /// Return a byte[] that contains the tlv
        /// </summary>
        public virtual byte[] Bytes => Data.ActualBytes();

        /// <summary>
        /// Points to the TLV data
        /// </summary>
        protected ByteArraySegment Data
        {
            get => _data;
            set
            {
                _data = value;

                // create a new TypeLength that points at the new ByteArrayAndOffset
                TypeLength = new TlvTypeLength(value)
                {
                    Length = value.Length - TlvTypeLength.TypeLengthLength
                };
            }
        }

        /// <summary>
        /// Interface to this TLVs type and length
        /// </summary>
        protected TlvTypeLength TypeLength;
    }
}