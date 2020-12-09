﻿/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

using System;
using System.IO;
using System.Net.NetworkInformation;
using PacketDotNet.Utils;
using PacketDotNet.Utils.Converters;

#if DEBUG
using log4net;
using System.Reflection;
#endif

namespace PacketDotNet.Ieee80211
{
    /// <summary>
    /// Base class of all 802.11 frame types
    /// </summary>
    public abstract class MacFrame : Packet
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

        private int GetOffsetForAddress(int addressIndex)
        {
            var offset = Header.Offset;

            offset += MacFields.Address1Position + MacFields.AddressLength * addressIndex;

            // the 4th address is AFTER the sequence control field so we need to skip past that
            // field
            if (addressIndex == 4)
                offset += MacFields.SequenceControlLength;

            return offset;
        }

        /// <summary>
        /// Frame control bytes are the first two bytes of the frame
        /// </summary>
        protected ushort FrameControlBytes
        {
            get
            {
                if (Header.Length >= MacFields.FrameControlPosition + MacFields.FrameControlLength)
                {
                    return EndianBitConverter.Big.ToUInt16(Header.Bytes,
                                                           Header.Offset);
                }

                return 0;
            }
            set => EndianBitConverter.Big.CopyBytes(value,
                                                    Header.Bytes,
                                                    Header.Offset);
        }

        /// <summary>
        /// Frame control field
        /// </summary>
        public FrameControlField FrameControl { get; set; }

        /// <summary>
        /// Duration bytes are the third and fourth bytes of the frame
        /// </summary>
        protected ushort DurationBytes
        {
            get
            {
                if (Header.Length >= MacFields.DurationIDPosition + MacFields.DurationIDLength)
                {
                    return EndianBitConverter.Little.ToUInt16(Header.Bytes,
                                                              Header.Offset + MacFields.DurationIDPosition);
                }

                return 0;
            }
            set => EndianBitConverter.Little.CopyBytes(value,
                                                       Header.Bytes,
                                                       Header.Offset + MacFields.DurationIDPosition);
        }

        /// <summary>
        /// Gets or sets the duration value. The value represents the number of microseconds
        /// the the wireless medium is expected to remain busy.
        /// </summary>
        /// <value>
        /// The duration field value
        /// </value>
        public DurationField Duration { get; set; }

        /// <summary>
        /// Writes the address into the specified address position.
        /// </summary>
        /// <remarks>
        /// The number of valid address positions in a MAC frame is determined by
        /// the type of frame. There are between 1 and 4 address fields in MAC frames
        /// </remarks>
        /// <param name="addressIndex">Zero based address to look up</param>
        /// <param name="address"></param>
        protected void SetAddress(int addressIndex, PhysicalAddress address)
        {
            var offset = GetOffsetForAddress(addressIndex);
            SetAddressByOffset(offset, address);
        }

        /// <summary>
        /// Writes the provided address into the backing <see cref="ByteArraySegment" />
        /// starting at the provided offset.
        /// </summary>
        /// <param name='offset'>
        /// The position where the address should start to be copied
        /// </param>
        /// <param name='address'>
        /// Address.
        /// </param>
        protected void SetAddressByOffset(int offset, PhysicalAddress address)
        {
            //We will replace no address with a MAC of all zer
            var hwAddress = address.Equals(PhysicalAddress.None) ? new byte[] { 0, 0, 0, 0, 0, 0 } : address.GetAddressBytes();

            // using the offset, set the address
            if (hwAddress.Length != MacFields.AddressLength)
            {
                throw new InvalidOperationException("address length " + hwAddress.Length + " not equal to the expected length of " + MacFields.AddressLength);
            }

            Array.Copy(hwAddress,
                       0,
                       Header.Bytes,
                       offset,
                       hwAddress.Length);
        }

        /// <summary>
        /// Gets the address. There can be up to four addresses in a MacFrame depending on its type.
        /// </summary>
        /// <returns>
        /// The address.
        /// </returns>
        /// <param name='addressIndex'>
        /// Address index.
        /// </param>
        protected PhysicalAddress GetAddress(int addressIndex)
        {
            var offset = GetOffsetForAddress(addressIndex);
            return GetAddressByOffset(offset);
        }

        /// <summary>
        /// Gets an address by offset.
        /// </summary>
        /// <returns>
        /// The address as the specified index.
        /// </returns>
        /// <param name='offset'>
        /// The offset into the packet buffer at which to start parsing the address.
        /// </param>
        protected PhysicalAddress GetAddressByOffset(int offset)
        {
            if (Header.Offset + Header.Length >= offset + MacFields.AddressLength)
            {
                var hwAddress = new byte[MacFields.AddressLength];
                Array.Copy(Header.Bytes,
                           offset,
                           hwAddress,
                           0,
                           hwAddress.Length);

                return new PhysicalAddress(hwAddress);
            }

            return PhysicalAddress.None;
        }

        /// <summary>
        /// Frame check sequence, the last thing in the 802.11 mac packet
        /// </summary>
        public uint FrameCheckSequence { get; set; }

        /// <summary>
        /// Recalculates and updates the frame check sequence.
        /// </summary>
        /// <remarks>After calling this method the FCS will be value regardless of what the packet contains.</remarks>
        public void UpdateFrameCheckSequence()
        {
            var bytes = Bytes;
            var length = AppendFcs ? bytes.Length - 4 : bytes.Length;
            FrameCheckSequence = (uint) Crc32.Compute(Bytes, 0, length);
        }

        /// <summary>
        /// Length of the frame header.
        /// This does not include the FCS, it represents only the header bytes that would
        /// would proceed any payload.
        /// </summary>
        public abstract int FrameSize { get; }

        /// <summary>
        /// Returns the number of bytes of payload data currently available in
        /// the buffer.
        /// </summary>
        /// <remarks>
        /// This method is used to work out how much space there is for the payload in the
        /// underlying ByteArraySegment. To find out the length of
        /// actual payload assigned to the packet use PayloadData.Length.
        /// </remarks>
        /// <value>
        /// The number of bytes of space available after the header for payload data.
        /// </value>
        protected int GetAvailablePayloadLength()
        {
            var payloadLength = Header.BytesLength - (Header.Offset + FrameSize);
            return payloadLength > 0 ? payloadLength : 0;
        }

        /// <summary>
        /// Parses the <see cref="ByteArraySegment" /> into a MacFrame.
        /// </summary>
        /// <returns>
        /// The parsed MacFrame or null if it could not be parsed.
        /// </returns>
        /// <param name="byteArraySegment">
        /// The bytes of the packet. byteArraySegment.Offset should point to the first byte in the mac frame.
        /// </param>
        /// <remarks>
        /// If the provided bytes dont contain the FCS then call <see cref="ParsePacket" /> instead. The presence of the
        /// FCS is usually determined by configuration of the device used to capture the packets.
        /// </remarks>
        public static MacFrame ParsePacketWithFcs(ByteArraySegment byteArraySegment)
        {
            if (byteArraySegment.Length < MacFields.FrameControlLength + MacFields.FrameCheckSequenceLength)
            {
                //There isn't enough data for there to be an FCS and a packet
                return null;
            }

            //remove the FCS from the buffer that we will pass to the packet parsers
            var basWithoutFcs = new ByteArraySegment(byteArraySegment.Bytes,
                                                     byteArraySegment.Offset,
                                                     byteArraySegment.Length - MacFields.FrameCheckSequenceLength,
                                                     byteArraySegment.BytesLength - MacFields.FrameCheckSequenceLength);

            var fcs = EndianBitConverter.Big.ToUInt32(byteArraySegment.Bytes,
                                                      (byteArraySegment.Offset + byteArraySegment.Length) - MacFields.FrameCheckSequenceLength);

            var frame = ParsePacket(basWithoutFcs);
            if (frame != null)
            {
                frame.AppendFcs = true;
                frame.FrameCheckSequence = fcs;
            }

            return frame;
        }

        /// <summary>
        /// Parses the <see cref="ByteArraySegment" /> into a MacFrame.
        /// </summary>
        /// <returns>
        /// The parsed MacFrame or null if it could not be parsed.
        /// </returns>
        /// <param name="byteArraySegment">
        /// The bytes of the packet. byteArraySegment.Offset should point to the first byte in the mac frame.
        /// </param>
        /// <remarks>
        /// If the provided bytes contain the FCS then call <see cref="ParsePacketWithFcs" /> instead. The presence of the
        /// FCS is usually determined by configuration of the device used to capture the packets.
        /// </remarks>
        public static MacFrame ParsePacket(ByteArraySegment byteArraySegment)
        {
            if (byteArraySegment.Length < MacFields.FrameControlLength)
            {
                //there isn't enough data to even try and work out what type of packet it is
                return null;
            }

            //this is a bit ugly as we will end up parsing the framecontrol field twice, once here and once
            //inside the packet constructor. Could create the framecontrol and pass it to the packet but I think that is equally ugly
            var frameControl = new FrameControlField(
                                                     EndianBitConverter.Big.ToUInt16(byteArraySegment.Bytes, byteArraySegment.Offset));

            MacFrame macFrame = null;

            Log.DebugFormat("SubType {0}", frameControl.SubType);

            switch (frameControl.SubType)
            {
                case FrameControlField.FrameSubTypes.ManagementAssociationRequest:
                {
                    macFrame = new AssociationRequestFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ManagementAssociationResponse:
                {
                    macFrame = new AssociationResponseFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ManagementReassociationRequest:
                {
                    macFrame = new ReassociationRequestFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ManagementReassociationResponse:
                {
                    macFrame = new AssociationResponseFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ManagementProbeRequest:
                {
                    macFrame = new ProbeRequestFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ManagementProbeResponse:
                {
                    macFrame = new ProbeResponseFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ManagementReserved0:
                {
                    break; //TODO
                }
                case FrameControlField.FrameSubTypes.ManagementReserved1:
                {
                    break; //TODO
                }
                case FrameControlField.FrameSubTypes.ManagementBeacon:
                {
                    macFrame = new BeaconFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ManagementAtim:
                {
                    break; //TODO
                }
                case FrameControlField.FrameSubTypes.ManagementDisassociation:
                {
                    macFrame = new DisassociationFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ManagementAuthentication:
                {
                    macFrame = new AuthenticationFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ManagementDeauthentication:
                {
                    macFrame = new DeauthenticationFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ManagementAction:
                {
                    macFrame = new ActionFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ManagementReserved3:
                {
                    break; //TODO
                }
                case FrameControlField.FrameSubTypes.ControlBlockAcknowledgmentRequest:
                {
                    macFrame = new BlockAcknowledgmentRequestFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ControlBlockAcknowledgment:
                {
                    macFrame = new BlockAcknowledgmentFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ControlPSPoll:
                {
                    break; //TODO
                }
                case FrameControlField.FrameSubTypes.ControlRts:
                {
                    macFrame = new RtsFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ControlCts:
                {
                    macFrame = new CtsFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ControlAck:
                {
                    macFrame = new AcknowledgmentFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ControlCFEnd:
                {
                    macFrame = new ContentionFreeEndFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.ControlCFEndCFACK:
                {
                    break; //TODO
                }
                case FrameControlField.FrameSubTypes.Data:
                case FrameControlField.FrameSubTypes.DataCFAck:
                case FrameControlField.FrameSubTypes.DataCFPoll:
                case FrameControlField.FrameSubTypes.DataCFAckCFPoll:
                {
                    macFrame = new DataDataFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.DataNullFunctionNoData:
                case FrameControlField.FrameSubTypes.DataCFAckNoData:
                case FrameControlField.FrameSubTypes.DataCFPollNoData:
                case FrameControlField.FrameSubTypes.DataCFAckCFPollNoData:
                {
                    macFrame = new NullDataFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.QosData:
                case FrameControlField.FrameSubTypes.QosDataAndCFAck:
                case FrameControlField.FrameSubTypes.QosDataAndCFPoll:
                case FrameControlField.FrameSubTypes.QosDataAndCFAckAndCFPoll:
                {
                    macFrame = new QosDataFrame(byteArraySegment);
                    break;
                }
                case FrameControlField.FrameSubTypes.QosNullData:
                case FrameControlField.FrameSubTypes.QosCFAck:
                case FrameControlField.FrameSubTypes.QosCFPoll:
                case FrameControlField.FrameSubTypes.QosCFAckAndCFPoll:
                {
                    macFrame = new QosNullDataFrame(byteArraySegment);
                    break;
                }
            }

            return macFrame;
        }

        /// <summary>
        /// Calculates the FCS value for the provided bytes and compares it to the FCS value passed to the method.
        /// </summary>
        /// <returns>
        /// true if the FCS for the provided bytes matches the FCS passed in, false if not.
        /// </returns>
        /// <param name='data'>
        /// The byte array for which the FCS will be calculated.
        /// </param>
        /// <param name='offset'>
        /// The offset into data of the first byte to be covered by the FCS.
        /// </param>
        /// <param name='length'>
        /// The number of bytes to calculate the FCS for.
        /// </param>
        /// <param name='fcs'>
        /// The FCS to compare to the one calculated for the provided data.
        /// </param>
        /// <remarks>
        /// This method can be used to check the validity of a packet before attempting to parse it with either
        /// <see cref="ParsePacket" /> or <see cref="ParsePacketWithFcs" />. Attempting to parse a corrupted buffer
        /// using these methods could cause unexpected exceptions.
        /// </remarks>
        public static bool PerformFcsCheck(byte[] data, int offset, int length, uint fcs)
        {
            // Cast to uint for proper comparison to FrameCheckSequence
            var check = (uint) Crc32.Compute(data, offset, length);
            return check == fcs;
        }

        /// <summary>
        /// FCSs the valid.
        /// </summary>
        /// <returns>
        /// The valid.
        /// </returns>
        public bool FcsValid
        {
            get
            {
                var packetBytes = Bytes;
                var packetLength = AppendFcs ? packetBytes.Length - MacFields.FrameCheckSequenceLength : packetBytes.Length;
                return PerformFcsCheck(packetBytes, 0, packetLength, FrameCheckSequence);
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether this <see cref="MacFrame" /> should include an FCS at the end
        /// of the array returned by Bytes.
        /// </summary>
        /// <value>
        /// <c>true</c> if append FCS should be appended; otherwise, <c>false</c>.
        /// </value>
        public bool AppendFcs { get; set; }

        /// <value>
        /// The option to return a ByteArraySegment means that this method
        /// is higher performance as the data can start at an offset other than
        /// the first byte.
        /// </value>
        public override ByteArraySegment BytesSegment
        {
            get
            {
                Log.Debug("");

                // ensure calculated values are properly updated
                RecursivelyUpdateCalculatedValues();

                // if we share memory with all of our sub packets we can take a
                // higher performance path to retrieve the bytes
                var totalPacketLength = TotalPacketLength;
                if (SharesMemoryWithSubPackets && (!AppendFcs || Header.Bytes.Length >= Header.Offset + totalPacketLength + MacFields.FrameCheckSequenceLength))
                {
                    var packetLength = totalPacketLength;
                    if (AppendFcs)
                    {
                        packetLength += MacFields.FrameCheckSequenceLength;
                        //We need to update the FCS field because this couldn't be done during 
                        //RecursivelyUpdateCalculatedValues because we didn't know where it would be
                        EndianBitConverter.Big.CopyBytes(FrameCheckSequence,
                                                         Header.Bytes,
                                                         Header.Offset + totalPacketLength);
                    }

                    // The high performance path that is often taken because it is called on
                    // packets that have not had their header, or any of their sub packets, resized
                    var newByteArraySegment = new ByteArraySegment(Header.Bytes,
                                                                   Header.Offset,
                                                                   packetLength);

                    Log.DebugFormat("SharesMemoryWithSubPackets, returning byte array {0}",
                                    newByteArraySegment);

                    return newByteArraySegment;
                }

                Log.Debug("rebuilding the byte array");

                var ms = new MemoryStream();

                var headerCopy = HeaderData;
                ms.Write(headerCopy, 0, headerCopy.Length);

                PayloadPacketOrData.Value.AppendToMemoryStream(ms);

                if (AppendFcs)
                {
                    var fcsBuffer = EndianBitConverter.Big.GetBytes(FrameCheckSequence);
                    ms.Write(fcsBuffer, 0, fcsBuffer.Length);
                }

                var newBytes = ms.ToArray();

                return new ByteArraySegment(newBytes, 0, newBytes.Length);
            }
        }

        /// <summary>
        /// ToString() override
        /// </summary>
        /// <returns>
        /// A <see cref="string" />
        /// </returns>
        public override string ToString()
        {
            return $"802.11 MacFrame: [{FrameControl}], {GetAddressString()} FCS {FrameCheckSequence}";
        }

        /// <summary>
        /// Returns a string with a description of the addresses used in the packet.
        /// This is used as a component of the string returned by ToString().
        /// </summary>
        /// <returns>
        /// The address string.
        /// </returns>
        protected abstract string GetAddressString();
    }
}