﻿/*
This file is part of PacketDotNet

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/
/*
 *  Copyright 2010 Evan Plaice <evanplaice@gmail.com>
 *  Copyright 2010 Chris Morgan <chmorgan@gmail.com>
 */

namespace PacketDotNet.Lldp
{
    /// <summary>
    /// The Chassis IDTLV bytes subtypes
    /// </summary>
    public enum ChassisSubType
    {
        /// <summary>A Chassis Component identifier</summary>
        /// <remarks>See IETF RFC 2737</remarks>
        ChassisComponent = 1,

        /// <summary>An Interface Alias identifier</summary>
        /// <remarks>See IETF RFC 2863</remarks>
        InterfaceAlias = 2,

        /// <summary>A Port Component identifier</summary>
        /// <remarks>See IETF RFC 2737</remarks>
        PortComponent = 3,

        /// <summary>A MAC (Media Access Control) Address identifier</summary>
        /// <remarks>See IEEE Std 802</remarks>
        MacAddress = 4,

        /// <summary>A Network Address (IP Address) Identifier</summary>
        /// <remarks>See IEEE Std 802</remarks>
        NetworkAddress = 5,

        /// <summary>An Interface Name identifier</summary>
        /// <remarks>See IEEE Std 802</remarks>
        InterfaceName = 6,

        /// <summary>A Locally Assigned identifier</summary>
        LocallyAssigned = 7
    }
}