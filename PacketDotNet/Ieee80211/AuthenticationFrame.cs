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
    /// Format of an 802.11 management authentication frame.
    /// </summary>
    public sealed class AuthenticationFrame : ManagementFrame
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="byteArraySegment">
        /// A <see cref="ByteArraySegment" />
        /// </param>
        public AuthenticationFrame(ByteArraySegment byteArraySegment)
        {
            Header = new ByteArraySegment(byteArraySegment);

            FrameControl = new FrameControlField(FrameControlBytes);
            Duration = new DurationField(DurationBytes);
            DestinationAddress = GetAddress(0);
            SourceAddress = GetAddress(1);
            BssId = GetAddress(2);
            SequenceControl = new SequenceControlField(SequenceControlBytes);
            AuthenticationAlgorithmNumber = AuthenticationAlgorithmNumberBytes;
            AuthenticationAlgorithmTransactionSequenceNumber = AuthenticationAlgorithmTransactionSequenceNumberBytes;

            if (byteArraySegment.Length > AuthenticationFields.InformationElement1Position)
            {
                //create a segment that just refers to the info element section
                var infoElementsSegment = new ByteArraySegment(byteArraySegment.Bytes,
                                                               byteArraySegment.Offset + AuthenticationFields.InformationElement1Position,
                                                               byteArraySegment.Length - AuthenticationFields.InformationElement1Position);

                InformationElements = new InformationElementList(infoElementsSegment);
            }
            else
            {
                InformationElements = new InformationElementList();
            }

            //cant set length until after we have handled the information elements
            //as they vary in length
            Header.Length = FrameSize;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationFrame" /> class.
        /// </summary>
        /// <param name='sourceAddress'>
        /// Source address.
        /// </param>
        /// <param name='destinationAddress'>
        /// Destination address.
        /// </param>
        /// <param name='bssId'>
        /// Bss identifier (MAC Address of Access Point).
        /// </param>
        /// <param name='informationElements'>
        /// Information elements.
        /// </param>
        public AuthenticationFrame
        (
            PhysicalAddress sourceAddress,
            PhysicalAddress destinationAddress,
            PhysicalAddress bssId,
            InformationElementList informationElements)
        {
            FrameControl = new FrameControlField();
            Duration = new DurationField();
            DestinationAddress = destinationAddress;
            SourceAddress = sourceAddress;
            BssId = bssId;
            SequenceControl = new SequenceControlField();
            InformationElements = new InformationElementList(informationElements);

            FrameControl.SubType = FrameControlField.FrameSubTypes.ManagementAuthentication;
        }

        /// <summary>
        /// Number used for selection of authentication algorithm
        /// </summary>
        public ushort AuthenticationAlgorithmNumber { get; set; }

        /// <summary>
        /// Sequence number to define the step of the authentication algorithm
        /// </summary>
        public ushort AuthenticationAlgorithmTransactionSequenceNumber { get; set; }

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
                                         AuthenticationFields.AuthAlgorithmNumLength +
                                         AuthenticationFields.AuthAlgorithmTransactionSequenceNumLength +
                                         AuthenticationFields.StatusCodeLength +
                                         InformationElements.Length;

        /// <summary>
        /// The information elements included in the frame
        /// </summary>
        public InformationElementList InformationElements { get; set; }

        /// <summary>
        /// Indicates the success or failure of the authentication operation
        /// </summary>
        public AuthenticationStatusCode StatusCode { get; set; }

        private ushort AuthenticationAlgorithmNumberBytes
        {
            get
            {
                if (Header.Length >=
                    AuthenticationFields.AuthAlgorithmNumPosition + AuthenticationFields.AuthAlgorithmNumLength)
                {
                    return EndianBitConverter.Little.ToUInt16(Header.Bytes,
                                                              Header.Offset + AuthenticationFields.AuthAlgorithmNumPosition);
                }

                return 0;
            }
            set => EndianBitConverter.Little.CopyBytes(value,
                                                       Header.Bytes,
                                                       Header.Offset + AuthenticationFields.AuthAlgorithmNumPosition);
        }

        private ushort AuthenticationAlgorithmTransactionSequenceNumberBytes
        {
            get
            {
                if (Header.Length >=
                    AuthenticationFields.AuthAlgorithmTransactionSequenceNumPosition + AuthenticationFields.AuthAlgorithmTransactionSequenceNumLength)
                {
                    return EndianBitConverter.Little.ToUInt16(Header.Bytes,
                                                              Header.Offset + AuthenticationFields.AuthAlgorithmTransactionSequenceNumPosition);
                }

                return 0;
            }
            set => EndianBitConverter.Little.CopyBytes(value,
                                                       Header.Bytes,
                                                       Header.Offset + AuthenticationFields.AuthAlgorithmTransactionSequenceNumPosition);
        }

        private AuthenticationStatusCode StatusCodeBytes
        {
            set => EndianBitConverter.Little.CopyBytes((ushort) value,
                                                       Header.Bytes,
                                                       Header.Offset + AuthenticationFields.StatusCodePosition);
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
            AuthenticationAlgorithmNumberBytes = AuthenticationAlgorithmNumber;
            AuthenticationAlgorithmTransactionSequenceNumberBytes = AuthenticationAlgorithmTransactionSequenceNumber;
            StatusCodeBytes = StatusCode;
            //we now know the backing buffer is big enough to contain the info elements so we can safely copy them in
            InformationElements.CopyTo(Header, Header.Offset + AuthenticationFields.InformationElement1Position);

            Header.Length = FrameSize;
        }
    }
}