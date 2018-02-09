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
 *  Copyright 2017 Chris Morgan <chmorgan@gmail.com>
 */
using System;

namespace PacketDotNet.Ieee80211
    {
        class LogicalLinkControlFields
        {
            public readonly static int DsapLength = 1;
            public readonly static int SsapLength = 1;
            public readonly static int ControlOrganizationLength = 4;
            public readonly static int TypeLength = 2;

            public readonly static int DsapPosition = 0;
            public readonly static int SsapPosition = DsapPosition + DsapLength;
            public readonly static int ControlOrganizationPosition = SsapPosition + SsapLength;
            public readonly static int TypePosition = ControlOrganizationPosition + ControlOrganizationLength;

            public readonly static int HeaderLength = TypePosition + TypeLength;

            static LogicalLinkControlFields()
            {
            }
        }
    }

