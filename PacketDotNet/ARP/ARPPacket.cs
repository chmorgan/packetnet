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
 *  Copyright 2011 Chris Morgan <chmorgan@gmail.com>
 */

using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Text;
using PacketDotNet.Ethernet;
using PacketDotNet.IP;
using PacketDotNet.MiscUtil.Utils;
using PacketDotNet.Utils;
using PacketDotNet.Utils.Conversion;

namespace PacketDotNet.ARP
{
    /// <summary>
    /// An ARP protocol packet.
    /// </summary>
    [Serializable]
    public class ARPPacket : InternetLinkLayerPacket
    {
#if DEBUG
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
#else
        // NOTE: No need to warn about lack of use, the compiler won't
        //       put any calls to 'log' here but we need 'log' to exist to compile
#pragma warning disable 0169, 0649
        private static readonly ILogInactive log;
#pragma warning restore 0169, 0649
#endif

        /// <value>
        /// Also known as HardwareType
        /// </value>
        virtual public LinkLayers HardwareAddressType
        {
            get
            {
                return (LinkLayers)EndianBitConverter.Big.ToUInt16(this.header.Bytes, this.header.Offset + ARPFields.HardwareAddressTypePosition);
            }

            set
            {
                var theValue = (UInt16)value;
                EndianBitConverter.Big.CopyBytes(theValue, this.header.Bytes, this.header.Offset + ARPFields.HardwareAddressTypePosition);
            }
        }

        /// <value>
        /// Also known as ProtocolType
        /// </value>
        virtual public EthernetPacketType ProtocolAddressType
        {
            get
            {
                return (EthernetPacketType)EndianBitConverter.Big.ToUInt16(this.header.Bytes, this.header.Offset + ARPFields.ProtocolAddressTypePosition);
            }

            set
            {
                var theValue = (UInt16)value;
                EndianBitConverter.Big.CopyBytes(theValue, this.header.Bytes, this.header.Offset + ARPFields.ProtocolAddressTypePosition);
            }
        }

        /// <value>
        /// Hardware address length field
        /// </value>
        virtual public int HardwareAddressLength
        {
            get
            {
                return this.header.Bytes[this.header.Offset + ARPFields.HardwareAddressLengthPosition];
            }

            set
            {
                this.header.Bytes[this.header.Offset + ARPFields.HardwareAddressLengthPosition] = (byte)value;
            }
        }

        /// <value>
        /// Protocol address length field
        /// </value>
        virtual public int ProtocolAddressLength
        {
            get
            {
                return this.header.Bytes[this.header.Offset + ARPFields.ProtocolAddressLengthPosition];
            }

            set
            {
                this.header.Bytes[this.header.Offset + ARPFields.ProtocolAddressLengthPosition] = (byte)value;
            }
        }

        /// <summary> Fetch the operation code.
        /// Usually one of ARPFields.{ARP_OP_REQ_CODE, ARP_OP_REP_CODE}.
        /// </summary>
        /// <summary> Sets the operation code.
        /// Usually one of ARPFields.{ARP_OP_REQ_CODE, ARP_OP_REP_CODE}.
        /// </summary>
        virtual public ARPOperation Operation
        {
            get
            {
                return (ARPOperation)EndianBitConverter.Big.ToInt16(this.header.Bytes, this.header.Offset + ARPFields.OperationPosition);
            }

            set
            {
                var theValue = (Int16)value;
                EndianBitConverter.Big.CopyBytes(theValue, this.header.Bytes, this.header.Offset + ARPFields.OperationPosition);
            }
        }

        /// <value>
        /// Upper layer protocol address of the sender, arp is used for IPv4, IPv6 uses NDP
        /// </value>
        virtual public System.Net.IPAddress SenderProtocolAddress
        {
            get
            {
                return IpPacket.GetIPAddress(System.Net.Sockets.AddressFamily.InterNetwork, this.header.Offset + ARPFields.SenderProtocolAddressPosition, this.header.Bytes);
            }

            set
            {
                // check that the address family is ipv4
                if (value.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    throw new InvalidOperationException("Family != IPv4, ARP is used for IPv4, NDP for IPv6");

                byte[] address = value.GetAddressBytes();
                Array.Copy((Array) address, (int) 0,
                           (Array) this.header.Bytes, (int) (this.header.Offset + ARPFields.SenderProtocolAddressPosition),
                           address.Length);
            }
        }

        /// <value>
        /// Upper layer protocol address of the target, arp is used for IPv4, IPv6 uses NDP
        /// </value>
        virtual public System.Net.IPAddress TargetProtocolAddress
        {
            get
            {
                return IpPacket.GetIPAddress(System.Net.Sockets.AddressFamily.InterNetwork, this.header.Offset + ARPFields.TargetProtocolAddressPosition, this.header.Bytes);
            }

            set
            {
                // check that the address family is ipv4
                if (value.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    throw new InvalidOperationException("Family != IPv4, ARP is used for IPv4, NDP for IPv6");

                byte[] address = value.GetAddressBytes();
                Array.Copy((Array) address, (int) 0,
                           (Array) this.header.Bytes, (int) (this.header.Offset + ARPFields.TargetProtocolAddressPosition),
                           address.Length);
            }
        }

        /// <value>
        /// Sender hardware address, usually an ethernet mac address
        /// </value>
        public virtual PhysicalAddress SenderHardwareAddress
        {
            get
            {
                //FIXME: this code is broken because it assumes that the address position is
                // a fixed position
                byte[] hwAddress = new byte[this.HardwareAddressLength];
                Array.Copy((Array) this.header.Bytes, (int) (this.header.Offset + ARPFields.SenderHardwareAddressPosition),
                           hwAddress, 0, hwAddress.Length);
                return new PhysicalAddress(hwAddress);
            }

            set
            {
                byte[] hwAddress = value.GetAddressBytes();

                // for now we only support ethernet addresses even though the arp protocol
                // makes provisions for varying length addresses
                if(hwAddress.Length != EthernetFields.MacAddressLength)
                {
                    throw new InvalidOperationException("expected physical address length of "
                                                               + EthernetFields.MacAddressLength
                                                               + " but it was "
                                                               + hwAddress.Length);
                }

                Array.Copy((Array) hwAddress, (int) 0,
                           (Array) this.header.Bytes, (int) (this.header.Offset + ARPFields.SenderHardwareAddressPosition),
                           hwAddress.Length);
            }
        }

        /// <value>
        /// Target hardware address, usually an ethernet mac address
        /// </value>
        public virtual PhysicalAddress TargetHardwareAddress
        {
            get
            {
                //FIXME: this code is broken because it assumes that the address position is
                // a fixed position
                byte[] hwAddress = new byte[this.HardwareAddressLength];
                Array.Copy((Array) this.header.Bytes, (int) (this.header.Offset + ARPFields.TargetHardwareAddressPosition),
                           hwAddress, 0,
                           hwAddress.Length);
                return new PhysicalAddress(hwAddress);
            }
            set
            {
                byte[] hwAddress = value.GetAddressBytes();

                // for now we only support ethernet addresses even though the arp protocol
                // makes provisions for varying length addresses
                if(hwAddress.Length != EthernetFields.MacAddressLength)
                {
                    throw new InvalidOperationException("expected physical address length of "
                                                               + EthernetFields.MacAddressLength
                                                               + " but it was "
                                                               + hwAddress.Length);
                }

                Array.Copy((Array) hwAddress, (int) 0,
                           (Array) this.header.Bytes, (int) (this.header.Offset + ARPFields.TargetHardwareAddressPosition),
                           hwAddress.Length);
            }
        }

        /// <summary> Fetch ascii escape sequence of the color associated with this packet type.</summary>
        override public String Color
        {
            get
            {
                return AnsiEscapeSequences.Purple;
            }
        }

        /// <summary>
        /// Create an ARPPacket from values
        /// </summary>
        /// <param name="Operation">
        /// A <see cref="ARPOperation"/>
        /// </param>
        /// <param name="TargetHardwareAddress">
        /// A <see cref="PhysicalAddress"/>
        /// </param>
        /// <param name="TargetProtocolAddress">
        /// A <see cref="System.Net.IPAddress"/>
        /// </param>
        /// <param name="SenderHardwareAddress">
        /// A <see cref="PhysicalAddress"/>
        /// </param>
        /// <param name="SenderProtocolAddress">
        /// A <see cref="System.Net.IPAddress"/>
        /// </param>
        public ARPPacket(ARPOperation Operation,
                         PhysicalAddress TargetHardwareAddress,
                         System.Net.IPAddress TargetProtocolAddress,
                         PhysicalAddress SenderHardwareAddress,
                         System.Net.IPAddress SenderProtocolAddress)
        {
            log.Debug("");

            // allocate memory for this packet
            int offset = 0;
            int length = ARPFields.HeaderLength;
            var headerBytes = new byte[length];
            this.header = new ByteArraySegment(headerBytes, offset, length);

            this.Operation = Operation;
            this.TargetHardwareAddress = TargetHardwareAddress;
            this.TargetProtocolAddress = TargetProtocolAddress;
            this.SenderHardwareAddress = SenderHardwareAddress;
            this.SenderProtocolAddress = SenderProtocolAddress;

            // set some internal properties to fully define the packet
            this.HardwareAddressType = LinkLayers.Ethernet;
            this.HardwareAddressLength = EthernetFields.MacAddressLength;

            this.ProtocolAddressType = EthernetPacketType.IpV4;
            this.ProtocolAddressLength = IPv4Fields.AddressLength;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="bas">
        /// A <see cref="ByteArraySegment"/>
        /// </param>
        public ARPPacket(ByteArraySegment bas)
        {
            this.header = new ByteArraySegment(bas)
            {
                Length = ARPFields.HeaderLength
            };

            // NOTE: no need to set the payloadPacketOrData field, arp packets have
            //       no payload
        }

        /// <summary cref="Packet.ToString(StringOutputType)" />
        public override string ToString(StringOutputType outputFormat)
        {
            var buffer = new StringBuilder();
            string color = "";
            string colorEscape = "";

            if(outputFormat == StringOutputType.Colored || outputFormat == StringOutputType.VerboseColored)
            {
                color = this.Color;
                colorEscape = AnsiEscapeSequences.Reset;
            }

            if(outputFormat == StringOutputType.Normal || outputFormat == StringOutputType.Colored)
            {
                // build the output string
                buffer.AppendFormat("{0}[ARPPacket: Operation={2}, SenderHardwareAddress={3}, TargetHardwareAddress={4}, SenderProtocolAddress={5}, TargetProtocolAddress={6}]{1}",
                    color,
                    colorEscape, this.Operation,
                    HexPrinter.PrintMACAddress(this.SenderHardwareAddress),
                    HexPrinter.PrintMACAddress(this.TargetHardwareAddress), this.SenderProtocolAddress, this.TargetProtocolAddress);
            }

            if(outputFormat == StringOutputType.Verbose || outputFormat == StringOutputType.VerboseColored)
            {
                // collect the properties and their value
                Dictionary<string,string> properties = new Dictionary<string,string>();
                properties.Add("hardware type", this.HardwareAddressType.ToString() + " (0x" + this.HardwareAddressType.ToString("x") + ")");
                properties.Add("protocol type", this.ProtocolAddressType.ToString() + " (0x" + this.ProtocolAddressType.ToString("x") + ")");
                properties.Add("operation", this.Operation.ToString() + " (0x" + this.Operation.ToString("x") + ")");
                properties.Add("source hardware address", HexPrinter.PrintMACAddress(this.SenderHardwareAddress));
                properties.Add("destination hardware address", HexPrinter.PrintMACAddress(this.TargetHardwareAddress));
                properties.Add("source protocol address", this.SenderProtocolAddress.ToString());
                properties.Add("destination protocol address", this.TargetProtocolAddress.ToString());

                // calculate the padding needed to right-justify the property names
                int padLength = RandomUtils.LongestStringLength(new List<string>(properties.Keys));

                // build the output string
                buffer.AppendLine("ARP:  ******* ARP - \"Address Resolution Protocol\" - offset=? length=" + this.TotalPacketLength);
                buffer.AppendLine("ARP:");
                foreach(var property in properties)
                {
                    buffer.AppendLine("ARP: " + property.Key.PadLeft(padLength) + " = " + property.Value);
                }
                buffer.AppendLine("ARP:");
            }

            // append the base string output
            buffer.Append((string) base.ToString(outputFormat));

            return buffer.ToString();
        }
    }
}