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

namespace PacketDotNet.Tcp
{
    /// <summary>
    /// AlternateChecksumRequest Option
    /// </summary>
    public class AlternateChecksumRequest : Option
    {
        #region Constructors

        /// <summary>
        /// Creates an Alternate Checksum Request Option
        ///  Used to negotiate an alternative checksum algorithm in a connection
        /// </summary>
        /// <param name="bytes">
        /// A <see cref="T:System.Byte[]"/>
        /// </param>
        /// <param name="offset">
        /// A <see cref="System.Int32"/>
        /// </param>
        /// <param name="length">
        /// A <see cref="System.Int32"/>
        /// </param>
        /// <remarks>
        /// References:
        ///  http://datatracker.ietf.org/doc/rfc1146/
        /// </remarks>
         public AlternateChecksumRequest(byte[] bytes, int offset, int length) :
            base(bytes, offset, length)
        { }

        #endregion

        #region Properties

        /// <summary>
        /// The Checksum
        /// </summary>
        public ChecksumAlgorighmType Checksum => (ChecksumAlgorighmType) this.Bytes[ChecksumFieldOffset];

        #endregion

        #region Methods

        /// <summary>
        /// Returns the Option info as a string
        /// </summary>
        /// <returns>
        /// A <see cref="System.String"/>
        /// </returns>
        public override string ToString()
        {
            return "[" + this.Kind.ToString() + ": ChecksumType=" + this.Checksum.ToString() + "]";
        }

        #endregion

        #region Members

        // the offset (in bytes) of the Checksum field
        const int ChecksumFieldOffset = 2;

        #endregion
    }
}