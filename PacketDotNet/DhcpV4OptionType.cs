﻿/*
This file is part of PacketDotNet.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

// ReSharper disable InconsistentNaming
// ReSharper disable IdentifierTypo

namespace PacketDotNet
{
    public enum DhcpV4OptionType : byte
    {
        Pad = 0,
        SubnetMask = 1,
        TimeOffset = 2,
        Router = 3,
        TimeServer = 4,
        NameServer = 5,
        DomainServer = 6,
        LogServer = 7,
        QuotesServer = 8,
        LPRServer = 9,
        ImpressServer = 10,
        RLPServer = 11,
        HostName = 12,
        BootFileSize = 13,
        MeritDumpFile = 14,
        DomainName = 15,
        SwapServer = 16,
        RootPath = 17,
        ExtensionFile = 18,
        ForwardOn = 19,
        SrcRteOn = 20,
        PolicyFilter = 21,
        MaxDGAssembly = 22,
        DefaultIPTTL = 23,
        MTUTimeout = 24,
        MTUPlateau = 25,
        MTUInterface = 26,
        MTUSubnet = 27,
        BroadcastAddress = 28,
        MaskDiscovery = 29,
        MaskSupplier = 30,
        RouterDiscovery = 31,
        RouterRequest = 32,
        StaticRoute = 33,
        Trailers = 34,
        ARPTimeout = 35,
        Ethernet = 36,
        DefaultTCPTTL = 37,
        KeepaliveTime = 38,
        KeepaliveData = 39,
        NISDomain = 40,
        NISServers = 41,
        NTPServers = 42,
        VendorSpecific = 43,
        NETBIOSNameSrv = 44,
        NETBIOSDistSrv = 45,
        NETBIOSNodeType = 46,
        NETBIOSScope = 47,
        XWindowFont = 48,
        XWindowManager = 49,
        AddressRequest = 50,
        AddressTime = 51,
        Overload = 52,
        DHCPMsgType = 53,
        DHCPServerId = 54,
        ParameterList = 55,
        DHCPMessage = 56,
        DHCPMaxMsgSize = 57,
        RenewalTime = 58,
        RebindingTime = 59,
        ClassId = 60,
        ClientId = 61,
        NetWare = 62,
        NetWare1 = 63,
        NISDomainName = 64,
        NISServerAddr = 65,
        ServerName = 66,
        BootFileName = 67,
        HomeAgentAddrs = 68,
        SMTPServer = 69,
        POP3Server = 70,
        NNTPServer = 71,
        WWWServer = 72,
        FingerServer = 73,
        IRCServer = 74,
        StreetTalkServer = 75,
        STDAServer = 76,
        UserClass = 77,
        DirectoryAgent = 78,
        ServiceScope = 79,
        RapidCommit = 80,
        ClientFQDN = 81,
        RelayAgentInformation = 82,
        iSNS = 83,
        NDSServers = 85,
        NDSTreeName = 86,
        NDSContext = 87,
        BCMCSControllerDomainNamelist = 88,
        BCMCSControllerIPv4addressoption = 89,
        Authentication = 90,
        ClientLastTransactionTimeoption = 91,
        AssociatedIpOption = 92,
        ClientSystem = 93,
        ClientNDI = 94,
        LDAP = 95,
        UUID = 97,
        UserAuth = 98,
        GEOCONF_CIVIC = 99,
        PCode = 100,
        TCode = 101,
        NetinfoAddress = 112,
        NetinfoTag = 113,
        URLN = 114,
        AutoConfig = 116,
        NameServiceSearch = 117,
        SubnetSelectionOption = 118,
        DomainSearch = 119,
        SIPServersDHCPOptionN = 120,
        ClasslessStaticRouteOption = 121,
        CCCN = 122,
        GeoConfOption = 123,
        VIVendorClass = 124,
        VIVendorSpecificInformation = 125,
        EtherbootSignature = 128,
        DOCSIS = 128,
        Kerneloptions = 129,
        CallServerIPaddress = 129,
        Ethernetinterface = 130,
        RemotestatisticsserverIPaddress = 131,
        IEEE802_1QVLANID = 132,
        IEEE802_1DPriority = 133,
        DiffservCodePoint = 134,
        HTTPProxyforphone = 135,
        SIPUAConfigurationServiceDomains = 141,
        Unassigned = 143,
        GeoLoc = 144,
        ForceRenewNonceCapable = 145,
        RDNSSSelection = 146,
        TFTPserveraddress = 150,
        Etherboot = 150,
        GRUBconfigurationpathname = 150,
        StatusCode = 151,
        BaseTime = 152,
        StartTimeOfState = 153,
        QueryStartTime = 154,
        QueryEndTime = 155,
        DHCPState = 156,
        DateSource1 = 157,
        DHCPCaptivePortal = 160,
        Etherboot1 = 175,
        IPTelephone = 176,
        Etherboot2 = 177,
        PXELINUXMagic = 208,
        ConfigurationFile = 209,
        PathPrefixNPathPrefixOption = 210,
        RebootTime4 = 211,
        v6RD = 212,
        SubnetAllocationOption = 220,
        VirtualSubnetSelectionOption = 221,
        End = 255
    }
}