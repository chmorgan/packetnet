﻿/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/
/*
 * Copyright 2012 Alan Rushforth <alan.rushforth@gmail.com>
 */

using System.Net.NetworkInformation;
using PacketDotNet.Utils;

namespace PacketDotNet.Ieee80211
{
    /// <summary>
    /// Contention free end frame.
    /// </summary>
    public sealed class ContentionFreeEndFrame : MacFrame
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="byteArraySegment">
        /// A <see cref="ByteArraySegment" />
        /// </param>
        public ContentionFreeEndFrame(ByteArraySegment byteArraySegment)
        {
            Header = new ByteArraySegment(byteArraySegment);

            FrameControl = new FrameControlField(FrameControlBytes);
            Duration = new DurationField(DurationBytes);
            ReceiverAddress = GetAddress(0);
            BssId = GetAddress(1);

            Header.Length = FrameSize;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ContentionFreeEndFrame" /> class.
        /// </summary>
        /// <param name='receiverAddress'>
        /// Receiver address.
        /// </param>
        /// <param name='bssId'>
        /// Bss identifier (MAC Address of the Access Point).
        /// </param>
        public ContentionFreeEndFrame
        (
            PhysicalAddress receiverAddress,
            PhysicalAddress bssId)
        {
            FrameControl = new FrameControlField();
            Duration = new DurationField();
            ReceiverAddress = receiverAddress;
            BssId = bssId;

            FrameControl.SubType = FrameControlField.FrameSubTypes.ControlCFEnd;
        }

        /// <summary>
        /// BSS ID
        /// </summary>
        public PhysicalAddress BssId { get; set; }

        /// <summary>
        /// Length of the frame
        /// </summary>
        public override int FrameSize => MacFields.FrameControlLength +
                                         MacFields.DurationIDLength +
                                         (MacFields.AddressLength * 2);

        /// <summary>
        /// Receiver address
        /// </summary>
        public PhysicalAddress ReceiverAddress { get; set; }

        /// <summary>
        /// Writes the current packet properties to the backing ByteArraySegment.
        /// </summary>
        public override void UpdateCalculatedValues()
        {
            if (Header == null || Header.Length > Header.BytesLength - Header.Offset || Header.Length < FrameSize)
            {
                Header = new ByteArraySegment(new byte[FrameSize]);
            }

            FrameControlBytes = FrameControl.Field;
            DurationBytes = Duration.Field;
            SetAddress(0, ReceiverAddress);
            SetAddress(1, BssId);

            Header.Length = FrameSize;
        }

        /// <summary>
        /// Returns a string with a description of the addresses used in the packet.
        /// This is used as a component of the string returned by ToString().
        /// </summary>
        /// <returns>
        /// The address string.
        /// </returns>
        protected override string GetAddressString()
        {
            return $"RA {ReceiverAddress} BSSID {BssId}";
        }
    }
}