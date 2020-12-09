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
using PacketDotNet.Utils.Converters;

namespace PacketDotNet.Ieee80211
{
    /// <summary>
    /// Deauthentication frame.
    /// </summary>
    public sealed class DeauthenticationFrame : ManagementFrame
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="byteArraySegment">
        /// A <see cref="ByteArraySegment" />
        /// </param>
        public DeauthenticationFrame(ByteArraySegment byteArraySegment)
        {
            Header = new ByteArraySegment(byteArraySegment);

            FrameControl = new FrameControlField(FrameControlBytes);
            Duration = new DurationField(DurationBytes);
            DestinationAddress = GetAddress(0);
            SourceAddress = GetAddress(1);
            BssId = GetAddress(2);
            SequenceControl = new SequenceControlField(SequenceControlBytes);
            Reason = ReasonBytes;

            Header.Length = FrameSize;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DeauthenticationFrame" /> class.
        /// </summary>
        /// <param name='sourceAddress'>
        /// Source address.
        /// </param>
        /// <param name='destinationAddress'>
        /// Destination address.
        /// </param>
        /// <param name='bssId'>
        /// Bss identifier (MAC Address of the Access Point).
        /// </param>
        public DeauthenticationFrame
        (
            PhysicalAddress sourceAddress,
            PhysicalAddress destinationAddress,
            PhysicalAddress bssId)
        {
            FrameControl = new FrameControlField();
            Duration = new DurationField();
            DestinationAddress = destinationAddress;
            SourceAddress = sourceAddress;
            BssId = bssId;
            SequenceControl = new SequenceControlField();

            FrameControl.SubType = FrameControlField.FrameSubTypes.ManagementDeauthentication;
        }

        /// <summary>
        /// Gets the size of the frame.
        /// </summary>
        /// <value>
        /// The size of the frame.
        /// </value>
        public override int FrameSize => MacFields.FrameControlLength +
                                         MacFields.DurationIDLength +
                                         (MacFields.AddressLength * 3) +
                                         MacFields.SequenceControlLength +
                                         DeauthenticationFields.ReasonCodeLength;

        /// <summary>
        /// Gets the reason for deauthentication.
        /// </summary>
        /// <value>
        /// The reason.
        /// </value>
        public ReasonCode Reason { get; set; }

        private ReasonCode ReasonBytes
        {
            get
            {
                if (Header.Length >= DeauthenticationFields.ReasonCodePosition + DeauthenticationFields.ReasonCodeLength)
                {
                    return (ReasonCode) EndianBitConverter.Little.ToUInt16(Header.Bytes,
                                                                           Header.Offset + DeauthenticationFields.ReasonCodePosition);
                }

                return ReasonCode.Unspecified;
            }
            set => EndianBitConverter.Little.CopyBytes((ushort) value,
                                                       Header.Bytes,
                                                       Header.Offset + DeauthenticationFields.ReasonCodePosition);
        }

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
            SetAddress(0, DestinationAddress);
            SetAddress(1, SourceAddress);
            SetAddress(2, BssId);
            SequenceControlBytes = SequenceControl.Field;
            ReasonBytes = Reason;

            Header.Length = FrameSize;
        }
    }
}