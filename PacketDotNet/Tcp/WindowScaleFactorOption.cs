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
    /// Window Scale Factor Option
    /// Expands the definition of the TCP window to 32 bits
    /// </summary>
    /// <remarks>
    /// References:
    /// http://datatracker.ietf.org/doc/rfc1323/
    /// </remarks>
    public class WindowScaleFactorOption : TcpOption
    {
        // the offset (in bytes) of the ScaleFactor Field
        private const int ScaleFactorFieldOffset = 2;

        /// <summary>
        /// Creates a Window Scale Factor Option
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
        public WindowScaleFactorOption(byte[] bytes, int offset, int length) :
            base(bytes, offset, length)
        { }

        /// <summary>
        /// The Window Scale Factor
        /// used as a multiplier to the window value
        /// The multiplier is equal to 1 left-shifted by the ScaleFactor
        /// So a scale factor of 7 would equal 1 &lt;&lt; 7 = 128
        /// </summary>
        public byte ScaleFactor
        {
            get => Bytes[ScaleFactorFieldOffset];
            set => Bytes[ScaleFactorFieldOffset] = value;
        }

        /// <summary>
        /// Returns the Option info as a string
        /// The multiplier is equal to a value of 1 left-shifted by the scale factor
        /// </summary>
        /// <returns>
        /// A <see cref="string" />
        /// </returns>
        public override string ToString()
        {
            return "[" + Kind + ": ScaleFactor=" + ScaleFactor + " (multiply by " + (1 << ScaleFactor) + ")]";
        }
    }
}