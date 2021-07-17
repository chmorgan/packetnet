/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

using System;
using System.IO;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using NUnit.Framework;
using PacketDotNet;
using PacketDotNet.Lldp;
using PacketDotNet.Utils;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType
{
    [TestFixture]
    public class LldpTest
    {
        [Test]
        public void ConstructFromValues()
        {
            var expectedChassisIDType = ChassisSubType.NetworkAddress;
            var expectedChassisIDNetworkAddress = new NetworkAddress(new IPAddress(new byte[] { 0x0A, 0x00, 0x01, 0x01 }));
            var expectedPortIDBytes = new byte[] { 0x30, 0x30, 0x31, 0x42, 0x35, 0x34, 0x39, 0x34, 0x35, 0x41, 0x38, 0x42, 0x3a, 0x50, 0x32 };
            ushort expectedTimeToLive = 120;
            var expectedPortDescription = "Port Description";
            var expectedSystemName = "SystemName";
            var expectedSystemDescription = "System Description";
            ushort expectedSystemCapabilitiesCapability = 18;
            ushort expectedSystemCapabilitiesEnabled = 16;
            var managementAddressNetworkAddress = new NetworkAddress(new IPAddress(new byte[] { 0x0A, 0x00, 0x01, 0x01 }));
            var managementAddressObjectIdentifier = "Object Identifier";
            uint managementAddressInterfaceNumber = 0x44060124;

            var expectedOrganizationUniqueIdentifier = new byte[] { 0x24, 0x10, 0x12 };
            var expectedOrganizationSubType = 2;
            var expectedOrganizationSpecificBytes = new byte[] { 0xBA, 0xAD, 0xF0, 0x0D };

            var valuesLLDPPacket = new LldpPacket();
            Console.WriteLine("valuesLLDPPacket.ToString() {0}", valuesLLDPPacket);
            valuesLLDPPacket.TlvCollection.Add(new ChassisIdTlv(expectedChassisIDType, expectedChassisIDNetworkAddress));
            Console.WriteLine("valuesLLDPPacket.ToString() {0}", valuesLLDPPacket);
            //valuesLLDPPacket.TlvCollection.Add(new PortId(lldpPacket, PortSubTypes.MacAddress, new PhysicalAddress(new byte[6] { 0x00, 0x1C, 0x23, 0xAF, 0x08, 0xF3 })));
            valuesLLDPPacket.TlvCollection.Add(new PortIdTlv(PortSubType.LocallyAssigned, expectedPortIDBytes));
            valuesLLDPPacket.TlvCollection.Add(new TimeToLiveTlv(expectedTimeToLive));
            valuesLLDPPacket.TlvCollection.Add(new PortDescriptionTlv(expectedPortDescription));
            valuesLLDPPacket.TlvCollection.Add(new SystemNameTlv(expectedSystemName));
            valuesLLDPPacket.TlvCollection.Add(new SystemDescriptionTlv(expectedSystemDescription));
            valuesLLDPPacket.TlvCollection.Add(new SystemCapabilitiesTlv(expectedSystemCapabilitiesCapability, expectedSystemCapabilitiesEnabled));
            valuesLLDPPacket.TlvCollection.Add(new ManagementAddressTlv(managementAddressNetworkAddress,
                                                                     InterfaceNumber.SystemPortNumber,
                                                                     managementAddressInterfaceNumber,
                                                                     managementAddressObjectIdentifier));

            valuesLLDPPacket.TlvCollection.Add(new OrganizationSpecificTlv(expectedOrganizationUniqueIdentifier,
                                                                        expectedOrganizationSubType,
                                                                        expectedOrganizationSpecificBytes));

            valuesLLDPPacket.TlvCollection.Add(new EndOfLldpduTlv());

            var lldpBytes = valuesLLDPPacket.Bytes;

            Console.WriteLine("valuesLLDPPacket.ToString() {0}", valuesLLDPPacket);

            // reparse these bytes back into a lldp packet
            var lldpPacket = new LldpPacket(new ByteArraySegment(lldpBytes));

            Console.WriteLine("lldpPacket.ToString() {0}", lldpPacket);

            var expectedTlvCount = 10;
            Assert.AreEqual(expectedTlvCount, lldpPacket.TlvCollection.Count);

            var count = 1;
            foreach (var tlv in lldpPacket.TlvCollection)
            {
                Console.WriteLine("Type: " + tlv.GetType());
                switch (count)
                {
                    case 1:
                    {
                        Assert.AreEqual(typeof(ChassisIdTlv), tlv.GetType());
                        var chassisID = (ChassisIdTlv) tlv;
                        Assert.AreEqual(ChassisSubType.NetworkAddress, chassisID.SubType);
                        Assert.AreEqual(typeof(NetworkAddress), chassisID.SubTypeValue.GetType());
                        Console.WriteLine(expectedChassisIDNetworkAddress.ToString());
                        Console.WriteLine(chassisID.SubTypeValue.ToString());
                        Assert.AreEqual(expectedChassisIDNetworkAddress, chassisID.SubTypeValue);
                        break;
                    }
                    case 2:
                    {
                        Assert.AreEqual(typeof(PortIdTlv), tlv.GetType());
                        var portID = (PortIdTlv) tlv;
                        Assert.AreEqual(PortSubType.LocallyAssigned, portID.SubType);
                        Assert.AreEqual(expectedPortIDBytes, portID.SubTypeValue);
                        //Assert.AreEqual(PortSubTypes.MacAddress, portID.SubType);
                        //var macAddress = new PhysicalAddress(new byte[6] { 0x00, 0x1C, 0x23, 0xAF, 0x08, 0xF3 });
                        //Assert.AreEqual(macAddress, portID.SubTypeValue);
                        break;
                    }
                    case 3:
                    {
                        Assert.AreEqual(typeof(TimeToLiveTlv), tlv.GetType());
                        Assert.AreEqual(expectedTimeToLive, ((TimeToLiveTlv) tlv).Seconds);
                        break;
                    }
                    case 4:
                    {
                        Assert.AreEqual(typeof(PortDescriptionTlv), tlv.GetType());
                        Assert.AreEqual(expectedPortDescription, ((PortDescriptionTlv) tlv).Description);
                        break;
                    }
                    case 5:
                    {
                        Assert.AreEqual(typeof(SystemNameTlv), tlv.GetType());
                        Assert.AreEqual(expectedSystemName, ((SystemNameTlv) tlv).Name);
                        break;
                    }
                    case 6:
                    {
                        Assert.AreEqual(typeof(SystemDescriptionTlv), tlv.GetType());
                        Assert.AreEqual(expectedSystemDescription, ((SystemDescriptionTlv) tlv).Description);
                        break;
                    }
                    case 7:
                    {
                        Assert.AreEqual(typeof(SystemCapabilitiesTlv), tlv.GetType());
                        var capabilities = (SystemCapabilitiesTlv) tlv;
                        Assert.IsTrue(capabilities.IsCapable(CapabilityOptions.Repeater));
                        Assert.IsTrue(capabilities.IsEnabled(CapabilityOptions.Router));
                        Assert.IsFalse(capabilities.IsCapable(CapabilityOptions.Bridge));
                        Assert.IsFalse(capabilities.IsCapable(CapabilityOptions.DocsisCableDevice));
                        Assert.IsFalse(capabilities.IsCapable(CapabilityOptions.Other));
                        Assert.IsFalse(capabilities.IsCapable(CapabilityOptions.StationOnly));
                        Assert.IsFalse(capabilities.IsCapable(CapabilityOptions.Telephone));
                        Assert.IsFalse(capabilities.IsCapable(CapabilityOptions.WLanAP));
                        break;
                    }
                    case 8:
                    {
                        Assert.AreEqual(typeof(ManagementAddressTlv), tlv.GetType());
                        var mgmtAdd = (ManagementAddressTlv) tlv;
                        Assert.AreEqual(IanaAddressFamily.IPv4, mgmtAdd.AddressSubType);
                        Assert.AreEqual(managementAddressNetworkAddress, mgmtAdd.Address);
                        Assert.AreEqual(InterfaceNumber.SystemPortNumber, mgmtAdd.InterfaceSubType);
                        Assert.AreEqual(managementAddressInterfaceNumber, mgmtAdd.InterfaceNumber);
                        var expectedObjIdLength = managementAddressObjectIdentifier.Length;
                        Assert.AreEqual(expectedObjIdLength, mgmtAdd.ObjIdLength);
                        Assert.AreEqual(managementAddressObjectIdentifier, mgmtAdd.ObjectIdentifier);
                        break;
                    }
                    case 9:
                    {
                        Assert.AreEqual(typeof(OrganizationSpecificTlv), tlv.GetType());
                        var orgSpecifig = (OrganizationSpecificTlv) tlv;
                        Assert.AreEqual(expectedOrganizationUniqueIdentifier, orgSpecifig.OrganizationUniqueID);
                        Assert.AreEqual(expectedOrganizationSubType, orgSpecifig.OrganizationDefinedSubType);
                        Assert.AreEqual(expectedOrganizationSpecificBytes, orgSpecifig.OrganizationDefinedInfoString);
                        break;
                    }
                    case 10:
                    {
                        Assert.AreEqual(typeof(EndOfLldpduTlv), tlv.GetType());
                        break;
                    }
                    default:
                    {
                        throw new ArgumentException();
                    }
                }

                // increment the counter
                count++;
            }
        }

        [Test]
        public void LLDPParsing()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "lldp.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var l = p.Extract<LldpPacket>();

            var count = 1;
            Console.WriteLine(l.TlvCollection.Count.ToString());
            foreach (var tlv in l.TlvCollection)
            {
                Console.WriteLine("Type: " + tlv.GetType());
                switch (count)
                {
                    case 1:
                    {
                        Assert.AreEqual(typeof(ChassisIdTlv), tlv.GetType());
                        var chassisID = (ChassisIdTlv) tlv;
                        Assert.AreEqual(chassisID.SubType, ChassisSubType.NetworkAddress);
                        Assert.AreEqual(typeof(NetworkAddress), chassisID.SubTypeValue.GetType());
                        var testAddress = new NetworkAddress(new IPAddress(new byte[] { 0xac, 0x10, 0x0a, 0x6d }));
                        Assert.AreEqual(testAddress, chassisID.SubTypeValue);
                        break;
                    }
                    case 2:
                    {
                        Assert.AreEqual(typeof(PortIdTlv), tlv.GetType());
                        var portID = (PortIdTlv) tlv;
                        Assert.AreEqual(PortSubType.LocallyAssigned, portID.SubType);
                        var subTypeValue = new byte[] { 0x30, 0x30, 0x31, 0x42, 0x35, 0x34, 0x39, 0x34, 0x35, 0x41, 0x38, 0x42, 0x3a, 0x50, 0x32 };
                        Assert.AreEqual(subTypeValue, portID.SubTypeValue);
                        break;
                    }
                    case 3:
                    {
                        Assert.AreEqual(typeof(TimeToLiveTlv), tlv.GetType());
                        Assert.AreEqual(180, ((TimeToLiveTlv) tlv).Seconds);
                        break;
                    }
                    case 4:
                    {
                        Assert.AreEqual(typeof(PortDescriptionTlv), tlv.GetType());
                        Assert.AreEqual("PC Port", ((PortDescriptionTlv) tlv).Description);
                        break;
                    }
                    case 5:
                    {
                        Assert.AreEqual(typeof(SystemNameTlv), tlv.GetType());
                        Assert.AreEqual("SEP001B54945A8B.elmec.ad", ((SystemNameTlv) tlv).Name);
                        break;
                    }
                    case 6:
                    {
                        Assert.AreEqual(typeof(SystemDescriptionTlv), tlv.GetType());
                        Assert.AreEqual("Cisco IP Phone CP-7911G,V2, SCCP11.8-4-3S", ((SystemDescriptionTlv) tlv).Description);
                        break;
                    }
                    case 7:
                    {
                        Assert.AreEqual(typeof(SystemCapabilitiesTlv), tlv.GetType());
                        var systemCapabilities = (SystemCapabilitiesTlv) tlv;
                        Assert.AreEqual(36, systemCapabilities.Capabilities);
                        Assert.AreEqual(36, systemCapabilities.Enabled);
                        Assert.IsTrue(systemCapabilities.IsCapable(CapabilityOptions.Bridge));
                        Assert.IsTrue(systemCapabilities.IsEnabled(CapabilityOptions.Telephone));
                        Assert.IsFalse(systemCapabilities.IsCapable(CapabilityOptions.Repeater));
                        Assert.IsFalse(systemCapabilities.IsEnabled(CapabilityOptions.WLanAP));
                        break;
                    }
                    case 8:
                    {
                        Assert.AreEqual(typeof(ManagementAddressTlv), tlv.GetType());
                        var managementAddress = (ManagementAddressTlv) tlv;
                        Assert.AreEqual(5, managementAddress.AddressLength);
                        Assert.AreEqual(1, (int) managementAddress.AddressSubType);
                        var mgmtAddress = new NetworkAddress(new IPAddress(new byte[] { 0xac, 0x10, 0x0a, 0x6d }));
                        Assert.AreEqual(mgmtAddress, managementAddress.Address);
                        Assert.AreEqual(1, (int) managementAddress.InterfaceSubType);
                        Assert.AreEqual(0, managementAddress.InterfaceNumber);
                        Assert.AreEqual(0, managementAddress.ObjIdLength);
                        break;
                    }
                    case 9:
                    {
                        Assert.AreEqual(typeof(OrganizationSpecificTlv), tlv.GetType());
                        var organizationSpecific = (OrganizationSpecificTlv) tlv;
                        Assert.AreEqual(new byte[] { 0x00, 0x12, 0x0f }, organizationSpecific.OrganizationUniqueID);
                        Assert.AreEqual(1, organizationSpecific.OrganizationDefinedSubType);
                        var infoString = new byte[] { 0x03, 0x00, 0x36, 0x00, 0x10 };
                        Assert.AreEqual(infoString, organizationSpecific.OrganizationDefinedInfoString);
                        break;
                    }
                    case 10:
                    {
                        Assert.AreEqual(typeof(EndOfLldpduTlv), tlv.GetType());
                        break;
                    }
                    default:
                    {
                        throw new ArgumentException();
                    }
                }

                // increment the counter
                count++;
            }
        }

        [Test]
        public void PrintString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "lldp.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var l = p.Extract<LldpPacket>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(l.ToString());
        }

        [Test]
        public void PrintVerboseString()
        {
            Console.WriteLine("Loading the sample capture file");
            var dev = new CaptureFileReaderDevice(NUnitSetupClass.CaptureDirectory + "lldp.pcap");
            dev.Open();
            Console.WriteLine("Reading packet data");
            PacketCapture c;
            dev.GetNextPacket(out c);
            var rawCapture = c.GetPacket();
            var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

            Console.WriteLine("Parsing");
            var l = p.Extract<LldpPacket>();

            Console.WriteLine("Printing human readable string");
            Console.WriteLine(l.ToString(StringOutputType.Verbose));
        }

        [Test]
        public void RandomPacket()
        {
            LldpPacket.RandomPacket();
        }
    }
}