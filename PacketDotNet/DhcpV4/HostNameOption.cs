﻿/*
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
 *  This file is licensed under the Apache License, Version 2.0.
 */

using System.Text;

// ReSharper disable InconsistentNaming
// ReSharper disable IdentifierTypo

namespace PacketDotNet.DhcpV4
{
    public class HostNameOption : DhcpV4Option
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HostNameOption" /> class.
        /// </summary>
        /// <param name="hostName">The hostName.</param>
        public HostNameOption(string hostName) : base(DhcpV4OptionType.HostName)
        {
            HostName = hostName;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HostNameOption" /> class.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <param name="offset">The buffer.</param>
        /// <param name="optionLength">The offset.</param>
        public HostNameOption(byte[] buffer, int offset, int optionLength) : base(DhcpV4OptionType.HostName)
        {
            HostName = Encoding.ASCII.GetString(buffer, offset, optionLength);
        }

        /// <inheritdoc />
        public override byte[] Data => Encoding.ASCII.GetBytes(HostName);

        /// <summary>
        /// Gets or sets the name of the host.
        /// </summary>
        public string HostName { get; set; }

        /// <inheritdoc />
        public override int Length => HostName.Length;

        /// <inheritdoc />
        public override string ToString()
        {
            return "HostName: " + HostName;
        }
    }
}