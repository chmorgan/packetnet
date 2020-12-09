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

using System;
using PacketDotNet.Utils;
using PacketDotNet.Utils.Converters;
#if DEBUG
using System.Reflection;
using log4net;

#endif

namespace PacketDotNet.Lldp
{
    /// <summary>
    /// TLV type and length are 2 bytes
    /// See http://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol#Frame_structure
    /// </summary>
    public class TlvTypeLength
    {
#if DEBUG
        private static readonly ILog Log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
#else
        // NOTE: No need to warn about lack of use, the compiler won't
        //       put any calls to 'log' here but we need 'log' to exist to compile
#pragma warning disable 0169, 0649
        private static readonly ILogInactive Log;
#pragma warning restore 0169, 0649
#endif

        /// <summary>
        /// Length in bytes of the TLV type and length fields
        /// </summary>
        public const int TypeLengthLength = 2;

        private const int LengthBits = 9;
        private const int LengthMask = 0x1FF;

        private const int MaximumTLVLength = 511;

        private const int TypeMask = 0xFE00;

        private readonly ByteArraySegment _byteArraySegment;

        /// <summary>
        /// Construct a TLVTypeLength for a Tlv
        /// </summary>
        /// <param name="byteArraySegment">
        /// A <see cref="ByteArraySegment" />
        /// </param>
        public TlvTypeLength(ByteArraySegment byteArraySegment)
        {
            _byteArraySegment = byteArraySegment;
        }

        /// <value>
        /// The TLV Value's Length
        /// NOTE: Value is the length of the TLV Value only, does not include the length
        /// of the type and length fields
        /// </value>
        public int Length
        {
            get
            {
                // get the length
                var typeAndLength = TypeAndLength;
                // remove the type info
                return LengthMask & typeAndLength;
            }

            // Length set is internal as the length of a TLV is automatically set based on
            // the TLVs content
            internal set
            {
                Log.DebugFormat("value {0}", value);

                if (value < 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), "Length must be a positive value");
                }

                if (value > MaximumTLVLength)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), "The maximum value for a TLV length is 511");
                }

                // save the old type
                var type = (ushort) (TypeMask & TypeAndLength);
                // set the length
                TypeAndLength = (ushort) (type | value);
            }
        }

        /// <value>
        /// The TLV Value's Type
        /// </value>
        public TlvType Type
        {
            get
            {
                // get the type
                var typeAndLength = TypeAndLength;
                // remove the length info
                return (TlvType) (typeAndLength >> LengthBits);
            }
            set
            {
                Log.DebugFormat("value of {0}", value);

                // shift type into the type position
                var type = (ushort) ((ushort) value << LengthBits);
                // save the old length
                var length = (ushort) (LengthMask & TypeAndLength);
                // set the type
                TypeAndLength = (ushort) (type | length);
            }
        }

        /// <value>
        /// A unsigned short representing the concatenated Type and Length
        /// </value>
        private ushort TypeAndLength
        {
            get => EndianBitConverter.Big.ToUInt16(_byteArraySegment.Bytes, _byteArraySegment.Offset);
            set => EndianBitConverter.Big.CopyBytes(value, _byteArraySegment.Bytes, _byteArraySegment.Offset);
        }
    }
}