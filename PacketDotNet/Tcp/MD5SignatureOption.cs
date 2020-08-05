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
 */

using System;

namespace PacketDotNet.Tcp
{
    /// <summary>
    /// MD5 Signature
    /// Carries the MD5 Digest used by the BGP protocol to
    /// ensure security between two endpoints
    /// </summary>
    /// <remarks>
    /// References:
    /// http://datatracker.ietf.org/doc/rfc2385/
    /// </remarks>
    public class MD5SignatureOption : TcpOption
    {
        // the offset (in bytes) of the MD5 Digest field
        private const int MD5DigestFieldOffset = 2;

        /// <summary>
        /// Creates a MD5 Signature Option
        /// </summary>
        /// <param name="bytes">
        /// A <see cref="T:System.Byte[]" />
        /// </param>
        /// <param name="offset">
        /// A <see cref="int" />
        /// </param>
        /// <param name="length">
        /// A <see cref="int" />
        /// </param>
        public MD5SignatureOption(byte[] bytes, int offset, int length) :
            base(bytes, offset, length)
        { }

        /// <summary>
        /// The MD5 Digest
        /// </summary>
        public byte[] MD5Digest
        {
            get
            {
                var data = new byte[Length - MD5DigestFieldOffset];
                Array.Copy(OptionData.Bytes, OptionData.Offset + MD5DigestFieldOffset, data, 0, data.Length);
                return data;
            }
            set => Array.Copy(value, 0, OptionData.Bytes, OptionData.Offset + MD5DigestFieldOffset, value.Length);
        }

        /// <summary>
        /// Returns the Option info as a string
        /// </summary>
        /// <returns>
        /// A <see cref="string" />
        /// </returns>
        public override string ToString()
        {
            return "[" + Kind + ": MD5Digest=0x" + MD5Digest + "]";
        }
    }
}