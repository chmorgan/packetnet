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
 * Copyright 2009 Chris Morgan <chmorgan@gmail.com>
 */

namespace PacketDotNet
{
    /// <summary>
    /// A struct containing length and position information about IPv6 Fields.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public struct IPv6Fields
    {
        /// <summary>
        /// The IP Version, Traffic Class, and Flow Label field length. These must be in one
        /// field due to boundary crossings.
        /// </summary>
        public static readonly int VersionTrafficClassFlowLabelLength = 4;

        /// <summary>
        /// The header extension length position.
        /// </summary>
        public static readonly int HeaderExtensionLengthPosition = 1;

        /// <summary>
        /// The fragment offset position.
        /// </summary>
        public static readonly int FragmentOffsetPosition = 2;

        /// <summary>
        /// The header extension data position.
        /// </summary>
        public static readonly int HeaderExtensionDataPosition = 2;

        /// <summary>
        /// The payload length field length.
        /// </summary>
        public static readonly int PayloadLengthLength = 2;

        /// <summary>
        /// The next header field length, identifies protocol encapsulated by the packet
        /// </summary>
        public static readonly int NextHeaderLength = 1;

        /// <summary>
        /// The hop limit field length.
        /// </summary>
        public static readonly int HopLimitLength = 1;

        /// <summary>
        /// Address field length
        /// </summary>
        public static readonly int AddressLength = 16;

        /// <summary>
        /// The byte position of the field line in the IPv6 header.
        /// This is where the IP version, Traffic Class, and Flow Label fields are.
        /// </summary>
        public static readonly int VersionTrafficClassFlowLabelPosition = 0;

        /// <summary>
        /// The byte position of the payload length field.
        /// </summary>
        public static readonly int PayloadLengthPosition;

        /// <summary>
        /// The byte position of the next header field. (Replaces the ipv4 protocol field)
        /// </summary>
        public static readonly int NextHeaderPosition;

        /// <summary>
        /// The byte position of the hop limit field.
        /// </summary>
        public static readonly int HopLimitPosition;

        /// <summary>
        /// The byte position of the source address field.
        /// </summary>
        public static readonly int SourceAddressPosition;

        /// <summary>
        /// The byte position of the destination address field.
        /// </summary>
        public static readonly int DestinationAddressPosition;

        /// <summary>
        /// The byte length of the IPv6 Header
        /// </summary>
        public static readonly int HeaderLength; // == 40

        /// <summary>
        /// The teredo port.
        /// </summary>
        public static readonly int TeredoPort = 3544;

        /// <summary>
        /// Commutes the field positions.
        /// </summary>
        static IPv6Fields()
        {
            PayloadLengthPosition = VersionTrafficClassFlowLabelPosition + VersionTrafficClassFlowLabelLength;
            NextHeaderPosition = PayloadLengthPosition + PayloadLengthLength;
            HopLimitPosition = NextHeaderPosition + NextHeaderLength;
            SourceAddressPosition = HopLimitPosition + HopLimitLength;
            DestinationAddressPosition = SourceAddressPosition + AddressLength;
            HeaderLength = DestinationAddressPosition + AddressLength;
        }
    }
}