﻿/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/
/*
 * Copyright 2012 Alan Rushforth <alan.rushforth@gmail.com>
 */

using System;
using System.Collections.Generic;
using System.Linq;
using PacketDotNet.Utils;

namespace PacketDotNet.Ieee80211
{
    /// <summary>
    /// A <see cref="T:System.Collections.Generic.List" /> of
    /// <see cref="InformationElement">InformationElements</see>.
    /// </summary>
    /// <remarks>
    /// The order and set of Information Elements allowed in a particular 802.11 frame type is dictated
    /// by the 802.11 standards.
    /// </remarks>
    public class InformationElementList : List<InformationElement>
    {
        /// <summary>
        /// Initializes an empty <see cref="InformationElementList" />.
        /// </summary>
        public InformationElementList()
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="InformationElementList" /> class.
        /// </summary>
        /// <param name='list'>
        /// The elements to be included in the list.
        /// </param>
        public InformationElementList(InformationElementList list)
            : base(list)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="InformationElementList" /> class.
        /// </summary>
        /// <param name="byteArraySegment">
        /// A <see cref="ByteArraySegment" /> containing one or more information elements.
        /// byteArraySegment.Offset should point to the first byte of the first Information Element.
        /// </param>
        public InformationElementList(ByteArraySegment byteArraySegment)
        {
            var index = 0;
            while (index + InformationElement.ElementLengthPosition < byteArraySegment.Length)
            {
                var ieStartPosition = byteArraySegment.Offset + index;
                var valueLength = byteArraySegment.Bytes[ieStartPosition + InformationElement.ElementLengthPosition];
                var ieLength = InformationElement.ElementIdLength + InformationElement.ElementLengthLength + valueLength;
                var availableLength = Math.Min(ieLength, byteArraySegment.Length - index);
                Add(new InformationElement(new ByteArraySegment(byteArraySegment.Bytes, ieStartPosition, availableLength)));

                index += ieLength;
            }
        }

        /// <summary>
        /// Gets a Byte[] containing the serialized
        /// <see cref="InformationElement">InformationElements</see>
        /// </summary>
        /// <value>
        /// The serialized <see cref="InformationElement">InformationElements</see>
        /// </value>
        public byte[] Bytes
        {
            get
            {
                var bytes = new byte[Length];
                var index = 0;
                foreach (var ie in this)
                {
                    var ieBytes = ie.Bytes;
                    Array.Copy(ieBytes, 0, bytes, index, ieBytes.Length);

                    index += ieBytes.Length;
                }

                return bytes;
            }
        }

        /// <summary>
        /// Gets the total length in bytes of the list if its elements were serialized into a byte array
        /// </summary>
        /// <value>
        /// The length
        /// </value>
        public int Length
        {
            get
            {
                var length = 0;
                foreach (var ie in this)
                {
                    length += ie.ElementLength;
                }

                return length;
            }
        }

        /// <summary>
        /// Finds all <see cref="InformationElement"></see> in the lists
        /// with the provided id.
        /// </summary>
        /// <returns>
        /// The <see cref="InformationElement">InformationElements</see> found, or an empty array if none are found
        /// </returns>
        /// <param name='id'>
        /// The Id to search for
        /// </param>
        public InformationElement[] FindById(InformationElement.ElementId id)
        {
            return (from ie in this
                    where ie.Id == id
                    select ie).ToArray();
        }

        /// <summary>
        /// Finds the first <see cref="InformationElement" /> in the list
        /// with the provided id.
        /// </summary>
        /// <returns>
        /// The first element with the provided Id or null if the list contains no relevant elements
        /// </returns>
        /// <param name='id'>
        /// The Id to search for
        /// </param>
        public InformationElement FindFirstById(InformationElement.ElementId id)
        {
            return (from ie in this
                    where ie.Id == id
                    select ie).FirstOrDefault();
        }

        /// <summary>
        /// Serialises the <see cref="InformationElement">InformationElements</see>
        /// in the list into the provided buffer.
        /// </summary>
        /// <param name='destination'>
        /// The <see cref="ByteArraySegment" /> to copy the elements into.
        /// </param>
        /// <param name='offset'>
        /// The offset into destination at which to start copy the <see cref="InformationElement">InformationElements</see>
        /// </param>
        /// <remarks>
        /// Ensure that the destination is large enough to contain serialized elements
        /// before calling this method
        /// </remarks>
        public void CopyTo(ByteArraySegment destination, int offset)
        {
            var index = 0;
            foreach (var ie in this)
            {
                var ieBytes = ie.Bytes;
                Array.Copy(ieBytes, 0, destination.Bytes, offset + index, ieBytes.Length);

                index += ieBytes.Length;
            }
        }
    }
}