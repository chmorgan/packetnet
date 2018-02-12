using System;
using System.Collections.Generic;
using System.Net;
using NUnit.Framework;
using PacketDotNet;
using PacketDotNet.OSPF;
using PacketDotNet.PPP;
using PacketDotNet.Utils;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Test.PacketType
{
    [TestFixture]
    internal class OSPFv2PacketTest
    {
        private const Int32 OSPF_DBD_INDEX = 9;
        private const Int32 OSPF_DBD_LSA_INDEX = 11;
        private const Int32 OSPF_HELLO_INDEX = 0;
        private const Int32 OSPF_LSA_INDEX = 23;
        private const Int32 OSPF_LSR_INDEX = 17;
        private const Int32 OSPF_LSU_INDEX = 18;
        private const Int32 OSPF_LSU_LSA_INDEX = 31;
        private OSPFv2Packet ddLSAPacket;
        private OSPFv2Packet ddPacket;

        private OSPFv2Packet helloPacket;

        private OSPFv2LSUpdatePacket lsaHolder;
        private OSPFv2Packet lsaPacket;
        private OSPFv2Packet lsrPacket;
        private OSPFv2Packet lsuPacket;

        private Boolean packetsLoaded;

        [SetUp]
        public void Init()
        {
            if (this.packetsLoaded)
                return;

            RawCapture raw;
            Int32 packetIndex = 0;
            var dev = new CaptureFileReaderDevice("../../CaptureFiles/ospfv2.pcap");
            dev.Open();


            while ((raw = dev.GetNextPacket()) != null)
            {
                OSPFv2Packet p =
                    (OSPFv2Packet) Packet.ParsePacket(raw.LinkLayerType, raw.Data).Extract(typeof(OSPFv2Packet));

                switch (packetIndex)
                {
                    case OSPF_HELLO_INDEX:
                        this.helloPacket = p;
                        break;
                    case OSPF_DBD_INDEX:
                        this.ddPacket = p;
                        break;
                    case OSPF_DBD_LSA_INDEX:
                        this.ddLSAPacket = p;
                        break;
                    case OSPF_LSU_INDEX:
                        this.lsuPacket = p;
                        break;
                    case OSPF_LSA_INDEX:
                        this.lsaPacket = p;
                        break;
                    case OSPF_LSR_INDEX:
                        this.lsrPacket = p;
                        break;
                    case OSPF_LSU_LSA_INDEX:
                        this.lsaHolder = (OSPFv2LSUpdatePacket) p;
                        break;
                    default: /* do nothing */ break;
                }

                packetIndex++;
            }

            dev.Close();

            this.packetsLoaded = true;
        }

        [Test]
        public void TestASExternalLSAConstruction()
        {
            //ctor 1
            ASExternalLSA al = new ASExternalLSA
            {
                LSAge = 90,
                Options = 0x22,
                LSType = LSAType.ASExternal,
                LinkStateID = IPAddress.Parse("1.1.1.1"),
                AdvertisingRouter = IPAddress.Parse("3.3.3.3"),
                LSSequenceNumber = 0x8000000F,
                Checksum = 0x3333,
                NetworkMask = IPAddress.Parse("255.255.255.252")
            };

            Assert.AreEqual(90, al.LSAge);
            Assert.AreEqual(0x22, al.Options);
            Assert.AreEqual(LSAType.ASExternal, al.LSType);
            Assert.AreEqual(IPAddress.Parse("1.1.1.1"), al.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("3.3.3.3"), al.AdvertisingRouter);
            Assert.AreEqual(0x8000000F, al.LSSequenceNumber);
            Assert.AreEqual(0x3333, al.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.252"), al.NetworkMask);
            Assert.AreEqual(0, al.ASExternalLinks.Count);
            Assert.AreEqual(24, al.Length);


            //ctor 2;
            ASExternalLink aslink = new ASExternalLink
            {
                EBit = 1,
                Metric = 100,
                ExternalRouteTag = 0,
                TOS = 0,
                ForwardingAddress = IPAddress.Parse("0.0.0.0")
            };

            List<ASExternalLink> links = new List<ASExternalLink>
            {
                aslink
            };

            al = new ASExternalLSA(links)
            {
                LSAge = 197,
                Options = 0x20,
                LSType = LSAType.ASExternal,
                LinkStateID = IPAddress.Parse("172.16.2.0"),
                AdvertisingRouter = IPAddress.Parse("2.2.2.2"),
                LSSequenceNumber = 0x80000001,
                Checksum = 0x3356,
                NetworkMask = IPAddress.Parse("255.255.255.0")
            };


            Assert.AreEqual(197, al.LSAge);
            Assert.AreEqual(0x20, al.Options);
            Assert.AreEqual(LSAType.ASExternal, al.LSType);
            Assert.AreEqual(IPAddress.Parse("172.16.2.0"), al.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("2.2.2.2"), al.AdvertisingRouter);
            Assert.AreEqual(0x80000001, al.LSSequenceNumber);
            Assert.AreEqual(0x3356, al.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), al.NetworkMask);
            Assert.AreEqual(1, al.ASExternalLinks.Count);
            Assert.AreEqual(36, al.Length);

            aslink = al.ASExternalLinks[0];
            Assert.AreEqual(1, aslink.EBit);
            Assert.AreEqual(100, aslink.Metric);
            Assert.AreEqual(0, aslink.ExternalRouteTag);
            Assert.AreEqual(0, aslink.TOS);
            Assert.AreEqual(IPAddress.Parse("0.0.0.0"), aslink.ForwardingAddress);
        }

        [Test]
        public void TestDBDPacket()
        {
            OSPFv2DDPacket dp = null;
            Assert.IsNotNull(this.ddPacket);
            Assert.AreEqual(OSPFVersion.OSPFv2, this.ddPacket.Version);
            Assert.AreEqual(OSPFPacketType.DatabaseDescription, this.ddPacket.Type);
            Assert.AreEqual(this.ddPacket is OSPFv2DDPacket, true);
            Assert.AreEqual(0xa052, this.ddPacket.Checksum);
            dp = (OSPFv2DDPacket) this.ddPacket;
            Assert.AreEqual(1098361214, dp.DDSequence);
            Assert.AreEqual(0, dp.LSAHeader.Count);
        }

        [Test]
        public void TestDDConstruction()
        {
            //test ctor 1
            OSPFv2DDPacket d = new OSPFv2DDPacket
            {
                InterfaceMTU = 1500,
                DDSequence = 1098361214,
                DBDescriptionOptions = 0x02
            };

            Assert.AreEqual(OSPFPacketType.DatabaseDescription, d.Type);
            Assert.AreEqual(1098361214, d.DDSequence);
            Assert.AreEqual(1500, d.InterfaceMTU);
            Assert.AreEqual(0x02, d.DBDescriptionOptions);

            //test re-creation
            Byte[] bytes = d.Bytes;
            OSPFv2DDPacket dp = new OSPFv2DDPacket(new ByteArraySegment(bytes));

            Assert.AreEqual(OSPFPacketType.DatabaseDescription, d.Type);
            Assert.AreEqual(1098361214, dp.DDSequence);
            Assert.AreEqual(1500, dp.InterfaceMTU);
            Assert.AreEqual(0x02, dp.DBDescriptionOptions);

            //test ctor 2
            List<LSA> lsas = new List<LSA>();

            LSA l = new LSA
            {
                AdvertisingRouter = IPAddress.Parse("192.168.170.3"),
                LinkStateID = IPAddress.Parse("192.168.170.3"),
                LSAge = 1,
                LSSequenceNumber = 0x80000001,
                LSType = LSAType.Router,
                Options = 0x02
            };
            lsas.Add(l);

            l = new LSA
            {
                AdvertisingRouter = IPAddress.Parse("192.168.170.2"),
                LinkStateID = IPAddress.Parse("80.212.16.0"),
                LSAge = 2,
                LSSequenceNumber = 0x80000001,
                LSType = LSAType.ASExternal,
                Options = 0x02
            };
            lsas.Add(l);

            l = new LSA
            {
                AdvertisingRouter = IPAddress.Parse("192.168.170.2"),
                LinkStateID = IPAddress.Parse("148.121.171.0"),
                LSAge = 2,
                LSSequenceNumber = 0x80000001,
                LSType = LSAType.ASExternal,
                Options = 0x02
            };
            lsas.Add(l);

            OSPFv2DDPacket ddl = new OSPFv2DDPacket(lsas)
            {
                InterfaceMTU = 1400,
                DDSequence = 123456789,
                DBDescriptionOptions = 0x03
            };

            Assert.AreEqual(OSPFPacketType.DatabaseDescription, ddl.Type);
            Assert.AreEqual(123456789, ddl.DDSequence);
            Assert.AreEqual(1400, ddl.InterfaceMTU);
            Assert.AreEqual(0x03, ddl.DBDescriptionOptions);

            Assert.AreEqual(3, ddl.LSAHeader.Count);

            Assert.AreEqual(ddl.LSAHeader[0].AdvertisingRouter, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(ddl.LSAHeader[0].LinkStateID, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(ddl.LSAHeader[0].LSAge, 1);
            Assert.AreEqual(ddl.LSAHeader[0].LSSequenceNumber, 0x80000001);
            Assert.AreEqual(ddl.LSAHeader[0].LSType, LSAType.Router);
            Assert.AreEqual(ddl.LSAHeader[0].Options, 0x02);

            Assert.AreEqual(ddl.LSAHeader[1].AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(ddl.LSAHeader[1].LinkStateID, IPAddress.Parse("80.212.16.0"));
            Assert.AreEqual(ddl.LSAHeader[1].LSAge, 2);
            Assert.AreEqual(ddl.LSAHeader[1].LSSequenceNumber, 0x80000001);
            Assert.AreEqual(ddl.LSAHeader[1].LSType, LSAType.ASExternal);
            Assert.AreEqual(ddl.LSAHeader[1].Options, 0x02);

            Assert.AreEqual(ddl.LSAHeader[2].AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(ddl.LSAHeader[2].LinkStateID, IPAddress.Parse("148.121.171.0"));
            Assert.AreEqual(ddl.LSAHeader[2].LSAge, 2);
            Assert.AreEqual(ddl.LSAHeader[2].LSSequenceNumber, 0x80000001);
            Assert.AreEqual(ddl.LSAHeader[2].LSType, LSAType.ASExternal);
            Assert.AreEqual(ddl.LSAHeader[2].Options, 0x02);
        }

        [Test]
        public void TestDDWithLSA()
        {
            OSPFv2DDPacket dp = null;
            Assert.IsNotNull(this.ddLSAPacket);
            Assert.AreEqual(OSPFVersion.OSPFv2, this.ddLSAPacket.Version);
            Assert.AreEqual(OSPFPacketType.DatabaseDescription, this.ddLSAPacket.Type);
            Assert.AreEqual(0xf067, this.ddLSAPacket.Checksum);
            dp = (OSPFv2DDPacket) this.ddLSAPacket;
            Assert.AreEqual(1098361214, dp.DDSequence);
            Assert.AreEqual(172, this.ddLSAPacket.PacketLength);

            List<LSA> lsas = dp.LSAHeader;
            Assert.AreEqual(7, lsas.Count);
            LSA l = lsas[0];
            Console.WriteLine(l);
            Assert.AreEqual(l.Checksum, 0x3a9c);
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(l.Length, 48);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(l.LSAge, 1);
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.LSType, LSAType.Router);
            Assert.AreEqual(l.Options, 0x02);

            l = lsas[1];
            Assert.AreEqual(l.Checksum, 0x2a49);
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(l.Length, 36);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("80.212.16.0"));
            Assert.AreEqual(l.LSAge, 2);
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.Options, 0x02);

            l = lsas[2];
            Assert.AreEqual(l.Checksum, 0x34a5);
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(l.Length, 36);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("148.121.171.0"));
            Assert.AreEqual(l.LSAge, 2);
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.Options, 0x02);

            l = lsas[3];
            Assert.AreEqual(l.Checksum, 0xd319);
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(l.Length, 36);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.130.120.0"));
            Assert.AreEqual(l.LSAge, 2);
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.Options, 0x02);

            l = lsas[4];
            Assert.AreEqual(l.Checksum, 0x3708);
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(l.Length, 36);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.168.0.0"));
            Assert.AreEqual(l.LSAge, 2);
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.Options, 0x02);

            l = lsas[5];
            Assert.AreEqual(l.Checksum, 0x2c12);
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(l.Length, 36);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.168.1.0"));
            Assert.AreEqual(l.LSAge, 2);
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.Options, 0x02);

            l = lsas[6];
            Assert.AreEqual(l.Checksum, 0x3341);
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(l.Length, 36);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.168.172.0"));
            Assert.AreEqual(l.LSAge, 2);
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.Options, 0x02);
        }

        [Test]
        public void TestHelloConstruction()
        {
            //test ctor 1
            OSPFv2HelloPacket p = new OSPFv2HelloPacket(IPAddress.Parse("255.255.255.0"), 2, 2)
            {
                RouterID = IPAddress.Parse("192.168.255.255"),
                AreaID = IPAddress.Parse("192.168.255.252"),

                HelloOptions = 0x02,
                DesignatedRouterID = IPAddress.Parse("192.168.1.1"),
                BackupRouterID = IPAddress.Parse("10.1.1.2")
            };

            Assert.AreEqual(OSPFVersion.OSPFv2, p.Version);
            Assert.AreEqual(OSPFPacketType.Hello, p.Type);
            Assert.AreEqual(0x02, p.HelloOptions);
            Assert.AreEqual(2, p.HelloInterval);
            Assert.AreEqual(2, p.RouterDeadInterval);
            Assert.AreEqual(IPAddress.Parse("192.168.255.255"), p.RouterID);
            Assert.AreEqual(IPAddress.Parse("192.168.255.252"), p.AreaID);
            Assert.AreEqual(IPAddress.Parse("192.168.1.1"), p.DesignatedRouterID);
            Assert.AreEqual(IPAddress.Parse("10.1.1.2"), p.BackupRouterID);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), p.NetworkMask);
            Assert.AreEqual(0, p.NeighborID.Count);

            //test re-creation
            Byte[] bytes = p.Bytes;
            OSPFv2HelloPacket hp = new OSPFv2HelloPacket(new ByteArraySegment(bytes));

            Assert.AreEqual(OSPFVersion.OSPFv2, hp.Version);
            Assert.AreEqual(OSPFPacketType.Hello, hp.Type);
            Assert.AreEqual(0x02, p.HelloOptions);
            Assert.AreEqual(2, hp.HelloInterval);
            Assert.AreEqual(2, hp.RouterDeadInterval);
            Assert.AreEqual(IPAddress.Parse("192.168.255.255"), hp.RouterID);
            Assert.AreEqual(IPAddress.Parse("192.168.255.252"), hp.AreaID);
            Assert.AreEqual(IPAddress.Parse("192.168.1.1"), hp.DesignatedRouterID);
            Assert.AreEqual(IPAddress.Parse("10.1.1.2"), hp.BackupRouterID);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), hp.NetworkMask);
            Assert.AreEqual(0, hp.NeighborID.Count);

            //test ctor 2
            List<IPAddress> neighbors = new List<IPAddress>
            {
                IPAddress.Parse("172.168.144.1"),
                IPAddress.Parse("123.192.133.255"),
                IPAddress.Parse("61.72.84.3"),
                IPAddress.Parse("127.0.0.1")
            };

            OSPFv2HelloPacket p2 = new OSPFv2HelloPacket(IPAddress.Parse("255.255.255.0"), 3, 4, neighbors);
            Assert.AreEqual(3, p2.HelloInterval);
            Assert.AreEqual(4, p2.RouterDeadInterval);
            Assert.AreEqual(4, p2.NeighborID.Count);
            Assert.AreEqual(IPAddress.Parse("172.168.144.1"), p2.NeighborID[0]);
            Assert.AreEqual(IPAddress.Parse("123.192.133.255"), p2.NeighborID[1]);
            Assert.AreEqual(IPAddress.Parse("61.72.84.3"), p2.NeighborID[2]);
            Assert.AreEqual(IPAddress.Parse("127.0.0.1"), p2.NeighborID[3]);
        }

        [Test]
        public void TestHelloPacket()
        {
            OSPFv2HelloPacket hp = null;
            Assert.IsNotNull(this.helloPacket);
            Assert.AreEqual(this.helloPacket is OSPFv2HelloPacket, true);
            hp = (OSPFv2HelloPacket) this.helloPacket;
            Assert.AreEqual(OSPFVersion.OSPFv2, this.helloPacket.Version);
            Assert.AreEqual(OSPFPacketType.Hello, this.helloPacket.Type);
            Assert.AreEqual(0x273b, this.helloPacket.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), hp.NetworkMask);
            Assert.AreEqual(0x02, hp.HelloOptions);
            Assert.AreEqual(0, hp.NeighborID.Count);
        }

        [Test]
        public void TestLinkStateRequests()
        {
            OSPFv2LSRequestPacket p = (OSPFv2LSRequestPacket) this.lsrPacket;
            List<LinkStateRequest> requests = p.LinkStateRequests;
            Assert.AreEqual(requests.Count, 7);

            LinkStateRequest r = requests[0];
            Assert.AreEqual(r.LSType, LSAType.Router);
            Assert.AreEqual(r.LinkStateID, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(r.AdvertisingRouter, IPAddress.Parse("192.168.170.3"));

            r = requests[1];
            Assert.AreEqual(r.LSType, LSAType.ASExternal);
            Assert.AreEqual(r.LinkStateID, IPAddress.Parse("80.212.16.0"));
            Assert.AreEqual(r.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));

            r = requests[2];
            Assert.AreEqual(r.LSType, LSAType.ASExternal);
            Assert.AreEqual(r.LinkStateID, IPAddress.Parse("148.121.171.0"));
            Assert.AreEqual(r.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));

            r = requests[3];
            Assert.AreEqual(r.LSType, LSAType.ASExternal);
            Assert.AreEqual(r.LinkStateID, IPAddress.Parse("192.130.120.0"));
            Assert.AreEqual(r.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));

            r = requests[4];
            Assert.AreEqual(r.LSType, LSAType.ASExternal);
            Assert.AreEqual(r.LinkStateID, IPAddress.Parse("192.168.0.0"));
            Assert.AreEqual(r.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));

            r = requests[5];
            Assert.AreEqual(r.LSType, LSAType.ASExternal);
            Assert.AreEqual(r.LinkStateID, IPAddress.Parse("192.168.1.0"));
            Assert.AreEqual(r.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));

            r = requests[6];
            Assert.AreEqual(r.LSType, LSAType.ASExternal);
            Assert.AreEqual(r.LinkStateID, IPAddress.Parse("192.168.172.0"));
            Assert.AreEqual(r.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
        }

        [Test]
        public void TestLSA()
        {
            RouterLSA rl;
            NetworkLSA nl;
            SummaryLSA sl;
            ASExternalLSA al;
            LSA l;

            Assert.AreNotEqual(null, this.lsaHolder);
            Assert.AreEqual(11, this.lsaHolder.LSANumber);
            Assert.AreEqual(11, this.lsaHolder.LSAUpdates.Count);

            l = this.lsaHolder.LSAUpdates[0];
            Assert.AreEqual(typeof(RouterLSA), l.GetType());
            rl = (RouterLSA) l;
            Assert.AreEqual(446, rl.LSAge);
            Assert.AreEqual(0x22, rl.Options);
            Assert.AreEqual(LSAType.Router, rl.LSType);
            Assert.AreEqual(IPAddress.Parse("5.5.5.5"), rl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("5.5.5.5"), rl.AdvertisingRouter);
            Assert.AreEqual(0x80000004, rl.LSSequenceNumber);
            Assert.AreEqual(0x7caa, rl.Checksum);
            Assert.AreEqual(48, rl.Length);
            Assert.AreEqual(0, rl.VBit);
            Assert.AreEqual(0, rl.EBit);
            Assert.AreEqual(0, rl.BBit);
            Assert.AreEqual(2, rl.RouterLinks.Count);

            RouterLink rlink = rl.RouterLinks[0];
            Assert.AreEqual(3, rlink.Type);
            Assert.AreEqual(IPAddress.Parse("192.168.20.0"), rlink.LinkID);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), rlink.LinkData);
            Assert.AreEqual(0, rlink.TOSNumber);
            Assert.AreEqual(10, rlink.Metric);

            rlink = rl.RouterLinks[1];
            Assert.AreEqual(2, rlink.Type);
            Assert.AreEqual(IPAddress.Parse("10.0.20.2"), rlink.LinkID);
            Assert.AreEqual(IPAddress.Parse("10.0.20.2"), rlink.LinkData);
            Assert.AreEqual(0, rlink.TOSNumber);
            Assert.AreEqual(10, rlink.Metric);

            l = this.lsaHolder.LSAUpdates[1];
            Assert.AreEqual(typeof(RouterLSA), l.GetType());
            rl = (RouterLSA) l;
            Assert.AreEqual(10, rl.LSAge);
            Assert.AreEqual(0x22, rl.Options);
            Assert.AreEqual(LSAType.Router, rl.LSType);
            Assert.AreEqual(IPAddress.Parse("4.4.4.4"), rl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("4.4.4.4"), rl.AdvertisingRouter);
            Assert.AreEqual(0x80000006, rl.LSSequenceNumber);
            Assert.AreEqual(0x36b1, rl.Checksum);
            Assert.AreEqual(36, rl.Length);
            Assert.AreEqual(0, rl.VBit);
            Assert.AreEqual(0, rl.EBit);
            Assert.AreEqual(1, rl.BBit);
            Assert.AreEqual(1, rl.RouterLinks.Count);

            rlink = rl.RouterLinks[0];
            Assert.AreEqual(3, rlink.Type);
            Assert.AreEqual(IPAddress.Parse("10.0.20.0"), rlink.LinkID);
            Assert.AreEqual(IPAddress.Parse("255.255.255.252"), rlink.LinkData);
            Assert.AreEqual(0, rlink.TOSNumber);
            Assert.AreEqual(10, rlink.Metric);

            l = this.lsaHolder.LSAUpdates[2];
            Assert.AreEqual(typeof(NetworkLSA), l.GetType());
            nl = (NetworkLSA) l;
            Assert.AreEqual(446, nl.LSAge);
            Assert.AreEqual(0x22, nl.Options);
            Assert.AreEqual(LSAType.Network, nl.LSType);
            Assert.AreEqual(IPAddress.Parse("10.0.20.2"), nl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("5.5.5.5"), nl.AdvertisingRouter);
            Assert.AreEqual(0x80000001, nl.LSSequenceNumber);
            Assert.AreEqual(0xf6ed, nl.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.252"), nl.NetworkMask);
            Assert.AreEqual(IPAddress.Parse("5.5.5.5"), nl.AttachedRouters[0]);
            Assert.AreEqual(IPAddress.Parse("4.4.4.4"), nl.AttachedRouters[1]);
            Assert.AreEqual(32, nl.Length);

            l = this.lsaHolder.LSAUpdates[3];
            Assert.AreEqual(typeof(SummaryLSA), l.GetType());
            sl = (SummaryLSA) l;
            Assert.AreEqual(11, sl.LSAge);
            Assert.AreEqual(0x22, sl.Options);
            Assert.AreEqual(LSAType.Summary, sl.LSType);
            Assert.AreEqual(IPAddress.Parse("192.168.10.0"), sl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("4.4.4.4"), sl.AdvertisingRouter);
            Assert.AreEqual(0x80000001, sl.LSSequenceNumber);
            Assert.AreEqual(0x1e7d, sl.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), sl.NetworkMask);
            Assert.AreEqual(30, sl.Metric);
            Assert.AreEqual(28, sl.Length);

            l = this.lsaHolder.LSAUpdates[4];
            Assert.AreEqual(typeof(SummaryLSA), l.GetType());
            sl = (SummaryLSA) l;
            Assert.AreEqual(11, sl.LSAge);
            Assert.AreEqual(0x22, sl.Options);
            Assert.AreEqual(LSAType.Summary, sl.LSType);
            Assert.AreEqual(IPAddress.Parse("10.0.10.0"), sl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("4.4.4.4"), sl.AdvertisingRouter);
            Assert.AreEqual(0x80000001, sl.LSSequenceNumber);
            Assert.AreEqual(0xd631, sl.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.252"), sl.NetworkMask);
            Assert.AreEqual(20, sl.Metric);
            Assert.AreEqual(28, sl.Length);

            l = this.lsaHolder.LSAUpdates[6];
            Assert.AreEqual(typeof(SummaryLSA), l.GetType());
            sl = (SummaryLSA) l;
            Assert.AreEqual(11, sl.LSAge);
            Assert.AreEqual(0x22, sl.Options);
            Assert.AreEqual(LSAType.SummaryASBR, sl.LSType);
            Assert.AreEqual(IPAddress.Parse("2.2.2.2"), sl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("4.4.4.4"), sl.AdvertisingRouter);
            Assert.AreEqual(0x80000001, sl.LSSequenceNumber);
            Assert.AreEqual(0x6fa0, sl.Checksum);
            Assert.AreEqual(IPAddress.Parse("0.0.0.0"), sl.NetworkMask);
            Assert.AreEqual(20, sl.Metric);
            Assert.AreEqual(28, sl.Length);

            l = this.lsaHolder.LSAUpdates[7];
            Assert.AreEqual(typeof(ASExternalLSA), l.GetType());
            al = (ASExternalLSA) l;
            Assert.AreEqual(197, al.LSAge);
            Assert.AreEqual(0x20, al.Options);
            Assert.AreEqual(LSAType.ASExternal, al.LSType);
            Assert.AreEqual(IPAddress.Parse("172.16.3.0"), al.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("2.2.2.2"), al.AdvertisingRouter);
            Assert.AreEqual(0x80000001, al.LSSequenceNumber);
            Assert.AreEqual(0x2860, al.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), al.NetworkMask);
            Assert.AreEqual(1, al.ASExternalLinks.Count);
            Assert.AreEqual(36, al.Length);

            ASExternalLink aslink = al.ASExternalLinks[0];
            Assert.AreEqual(aslink.EBit, 1);
            Assert.AreEqual(100, aslink.Metric);
            Assert.AreEqual(0, aslink.ExternalRouteTag);
            Assert.AreEqual(0, aslink.TOS);
            Assert.AreEqual(IPAddress.Parse("0.0.0.0"), aslink.ForwardingAddress);

            l = this.lsaHolder.LSAUpdates[8];
            Assert.AreEqual(typeof(ASExternalLSA), l.GetType());
            al = (ASExternalLSA) l;
            Assert.AreEqual(197, al.LSAge);
            Assert.AreEqual(0x20, al.Options);
            Assert.AreEqual(LSAType.ASExternal, al.LSType);
            Assert.AreEqual(IPAddress.Parse("172.16.2.0"), al.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("2.2.2.2"), al.AdvertisingRouter);
            Assert.AreEqual(0x80000001, al.LSSequenceNumber);
            Assert.AreEqual(0x3356, al.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), al.NetworkMask);
            Assert.AreEqual(1, al.ASExternalLinks.Count);
            Assert.AreEqual(36, al.Length);

            aslink = al.ASExternalLinks[0];
            Assert.AreEqual(aslink.EBit, 1);
            Assert.AreEqual(100, aslink.Metric);
            Assert.AreEqual(0, aslink.ExternalRouteTag);
            Assert.AreEqual(0, aslink.TOS);
            Assert.AreEqual(IPAddress.Parse("0.0.0.0"), aslink.ForwardingAddress);
        }

        [Test]
        public void TestLSAPacket()
        {
            Assert.IsNotNull(this.lsaPacket);
            Assert.AreEqual(OSPFVersion.OSPFv2, this.lsaPacket.Version);
            Assert.AreEqual(OSPFPacketType.LinkStateAcknowledgment, this.lsaPacket.Type);
            Assert.AreEqual(0xe95e, this.lsaPacket.Checksum);
            Assert.AreEqual(284, this.lsaPacket.PacketLength);
            Assert.AreEqual(IPAddress.Parse("0.0.0.1"), this.lsaPacket.AreaID);
            OSPFv2LSAPacket ack = (OSPFv2LSAPacket) this.lsaPacket;
            Assert.AreEqual(13, ack.LSAAcknowledge.Count);

            LSA l = ack.LSAAcknowledge[0];
            Assert.AreEqual(l.LSAge, 2);
            Assert.AreEqual(l.Options, 2);
            Assert.AreEqual(l.LSType, LSAType.Router);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.Checksum, 0x3a9c);
            Assert.AreEqual(l.Length, 48);

            l = ack.LSAAcknowledge[1];
            Assert.AreEqual(l.LSAge, 3);
            Assert.AreEqual(l.Options, 2);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("80.212.16.0"));
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.Checksum, 0x2a49);
            Assert.AreEqual(l.Length, 36);

            l = ack.LSAAcknowledge[2];
            Assert.AreEqual(l.LSAge, 3);
            Assert.AreEqual(l.Options, 2);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("148.121.171.0"));
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.Checksum, 0x34a5);
            Assert.AreEqual(l.Length, 36);

            l = ack.LSAAcknowledge[3];
            Assert.AreEqual(l.LSAge, 3);
            Assert.AreEqual(l.Options, 2);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.130.120.0"));
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.Checksum, 0xd319);
            Assert.AreEqual(l.Length, 36);

            l = ack.LSAAcknowledge[4];
            Assert.AreEqual(l.LSAge, 3);
            Assert.AreEqual(l.Options, 2);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.168.0.0"));
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.Checksum, 0x3708);
            Assert.AreEqual(l.Length, 36);

            l = ack.LSAAcknowledge[5];
            Assert.AreEqual(l.LSAge, 3);
            Assert.AreEqual(l.Options, 2);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.168.1.0"));
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.Checksum, 0x2c12);
            Assert.AreEqual(l.Length, 36);

            l = ack.LSAAcknowledge[6];
            Assert.AreEqual(l.LSAge, 3);
            Assert.AreEqual(l.Options, 2);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.168.172.0"));
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.Checksum, 0x3341);
            Assert.AreEqual(l.Length, 36);

            l = ack.LSAAcknowledge[7];
            Assert.AreEqual(l.LSAge, 1);
            Assert.AreEqual(l.Options, 2);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("148.121.171.0"));
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.Checksum, 0x2eaa);
            Assert.AreEqual(l.Length, 36);

            l = ack.LSAAcknowledge[8];
            Assert.AreEqual(l.LSAge, 1);
            Assert.AreEqual(l.Options, 2);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.130.120.0"));
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.Checksum, 0xcd1e);
            Assert.AreEqual(l.Length, 36);

            l = ack.LSAAcknowledge[9];
            Assert.AreEqual(l.LSAge, 1);
            Assert.AreEqual(l.Options, 2);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.168.0.0"));
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.Checksum, 0x310d);
            Assert.AreEqual(l.Length, 36);

            l = ack.LSAAcknowledge[10];
            Assert.AreEqual(l.LSAge, 1);
            Assert.AreEqual(l.Options, 2);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.168.1.0"));
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.Checksum, 0x2617);
            Assert.AreEqual(l.Length, 36);

            l = ack.LSAAcknowledge[11];
            Assert.AreEqual(l.LSAge, 1);
            Assert.AreEqual(l.Options, 2);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("192.168.172.0"));
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.Checksum, 0x2d46);
            Assert.AreEqual(l.Length, 36);

            l = ack.LSAAcknowledge[12];
            Assert.AreEqual(l.LSAge, 1);
            Assert.AreEqual(l.Options, 2);
            Assert.AreEqual(l.LSType, LSAType.ASExternal);
            Assert.AreEqual(l.LinkStateID, IPAddress.Parse("80.212.16.0"));
            Assert.AreEqual(l.AdvertisingRouter, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(l.LSSequenceNumber, 0x80000001);
            Assert.AreEqual(l.Checksum, 0x244e);
            Assert.AreEqual(l.Length, 36);
        }

        [Test]
        public void TestLSAPacketConstruction()
        {
            //test ctor 1
            OSPFv2LSAPacket p = new OSPFv2LSAPacket();

            Assert.AreEqual(OSPFPacketType.LinkStateAcknowledgment, p.Type);

            //test re-creation
            Byte[] bytes = p.Bytes;
            OSPFv2DDPacket p2 = new OSPFv2DDPacket(new ByteArraySegment(bytes));

            Assert.AreEqual(OSPFPacketType.LinkStateAcknowledgment, p2.Type);

            //test ctor 2
            List<LSA> lsas = new List<LSA>();
            LSA l = new LSA
            {
                AdvertisingRouter = IPAddress.Parse("192.168.170.3"),
                LinkStateID = IPAddress.Parse("192.168.170.3"),
                LSAge = 1,
                LSSequenceNumber = 0x80000001,
                LSType = LSAType.Router,
                Options = 0x02
            };
            lsas.Add(l);

            l = new LSA
            {
                AdvertisingRouter = IPAddress.Parse("192.168.170.2"),
                LinkStateID = IPAddress.Parse("80.212.16.0"),
                LSAge = 2,
                LSSequenceNumber = 0x80000001,
                LSType = LSAType.ASExternal,
                Options = 0x02
            };
            lsas.Add(l);

            l = new LSA
            {
                AdvertisingRouter = IPAddress.Parse("192.168.170.2"),
                LinkStateID = IPAddress.Parse("148.121.171.0"),
                LSAge = 2,
                LSSequenceNumber = 0x80000001,
                LSType = LSAType.ASExternal,
                Options = 0x02
            };
            lsas.Add(l);

            OSPFv2LSAPacket p3 = new OSPFv2LSAPacket(lsas);
            Assert.AreEqual(OSPFPacketType.LinkStateAcknowledgment, p3.Type);

            Assert.AreEqual(3, p3.LSAAcknowledge.Count);

            Assert.AreEqual(p3.LSAAcknowledge[0].AdvertisingRouter, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(p3.LSAAcknowledge[0].LinkStateID, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(p3.LSAAcknowledge[0].LSAge, 1);
            Assert.AreEqual(p3.LSAAcknowledge[0].LSSequenceNumber, 0x80000001);
            Assert.AreEqual(p3.LSAAcknowledge[0].LSType, LSAType.Router);
            Assert.AreEqual(p3.LSAAcknowledge[0].Options, 0x02);

            Assert.AreEqual(p3.LSAAcknowledge[1].AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(p3.LSAAcknowledge[1].LinkStateID, IPAddress.Parse("80.212.16.0"));
            Assert.AreEqual(p3.LSAAcknowledge[1].LSAge, 2);
            Assert.AreEqual(p3.LSAAcknowledge[1].LSSequenceNumber, 0x80000001);
            Assert.AreEqual(p3.LSAAcknowledge[1].LSType, LSAType.ASExternal);
            Assert.AreEqual(p3.LSAAcknowledge[1].Options, 0x02);

            Assert.AreEqual(p3.LSAAcknowledge[2].AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
            Assert.AreEqual(p3.LSAAcknowledge[2].LinkStateID, IPAddress.Parse("148.121.171.0"));
            Assert.AreEqual(p3.LSAAcknowledge[2].LSAge, 2);
            Assert.AreEqual(p3.LSAAcknowledge[2].LSSequenceNumber, 0x80000001);
            Assert.AreEqual(p3.LSAAcknowledge[2].LSType, LSAType.ASExternal);
            Assert.AreEqual(p3.LSAAcknowledge[2].Options, 0x02);
        }

        [Test]
        public void TestLSRConstruction()
        {
            //test ctor 1
            OSPFv2LSRequestPacket p = new OSPFv2LSRequestPacket
            {
                RouterID = IPAddress.Parse("192.168.255.255"),
                AreaID = IPAddress.Parse("192.168.255.252")
            };

            Assert.AreEqual(OSPFVersion.OSPFv2, p.Version);
            Assert.AreEqual(OSPFPacketType.LinkStateRequest, p.Type);

            Assert.AreEqual(IPAddress.Parse("192.168.255.255"), p.RouterID);
            Assert.AreEqual(IPAddress.Parse("192.168.255.252"), p.AreaID);

            //test re-creation
            Byte[] bytes = p.Bytes;
            OSPFv2LSRequestPacket lp = new OSPFv2LSRequestPacket(new ByteArraySegment(bytes));

            Assert.AreEqual(OSPFVersion.OSPFv2, lp.Version);
            Assert.AreEqual(OSPFPacketType.LinkStateRequest, lp.Type);

            Assert.AreEqual(IPAddress.Parse("192.168.255.255"), lp.RouterID);
            Assert.AreEqual(IPAddress.Parse("192.168.255.252"), lp.AreaID);

            //test ctor 2
            List<LinkStateRequest> lsrs = new List<LinkStateRequest>();

            LinkStateRequest r = new LinkStateRequest
            {
                LSType = LSAType.Router,
                LinkStateID = IPAddress.Parse("192.168.170.3"),
                AdvertisingRouter = IPAddress.Parse("192.168.170.3")
            };
            lsrs.Add(r);

            r = new LinkStateRequest
            {
                LSType = LSAType.ASExternal,
                LinkStateID = IPAddress.Parse("80.212.16.0"),
                AdvertisingRouter = IPAddress.Parse("192.168.170.2")
            };
            lsrs.Add(r);

            r = new LinkStateRequest
            {
                LSType = LSAType.Network,
                LinkStateID = IPAddress.Parse("148.121.171.0"),
                AdvertisingRouter = IPAddress.Parse("192.168.170.2")
            };
            lsrs.Add(r);

            OSPFv2LSRequestPacket lp2 = new OSPFv2LSRequestPacket(lsrs)
            {
                RouterID = IPAddress.Parse("10.0.1.255"),
                AreaID = IPAddress.Parse("10.0.2.252")
            };

            Assert.AreEqual(OSPFVersion.OSPFv2, lp2.Version);
            Assert.AreEqual(OSPFPacketType.LinkStateRequest, lp2.Type);

            Assert.AreEqual(IPAddress.Parse("10.0.1.255"), lp2.RouterID);
            Assert.AreEqual(IPAddress.Parse("10.0.2.252"), lp2.AreaID);

            Assert.AreEqual(lp2.LinkStateRequests[0].LSType, LSAType.Router);
            Assert.AreEqual(lp2.LinkStateRequests[0].LinkStateID, IPAddress.Parse("192.168.170.3"));
            Assert.AreEqual(lp2.LinkStateRequests[0].AdvertisingRouter, IPAddress.Parse("192.168.170.3"));

            Assert.AreEqual(lp2.LinkStateRequests[1].LSType, LSAType.ASExternal);
            Assert.AreEqual(lp2.LinkStateRequests[1].LinkStateID, IPAddress.Parse("80.212.16.0"));
            Assert.AreEqual(lp2.LinkStateRequests[1].AdvertisingRouter, IPAddress.Parse("192.168.170.2"));

            Assert.AreEqual(lp2.LinkStateRequests[2].LSType, LSAType.Network);
            Assert.AreEqual(lp2.LinkStateRequests[2].LinkStateID, IPAddress.Parse("148.121.171.0"));
            Assert.AreEqual(lp2.LinkStateRequests[2].AdvertisingRouter, IPAddress.Parse("192.168.170.2"));
        }

        [Test]
        public void TestLSRPacket()
        {
            OSPFv2LSRequestPacket lp = null;
            Assert.IsNotNull(this.lsrPacket);
            Assert.AreEqual(OSPFVersion.OSPFv2, this.lsrPacket.Version);
            Assert.AreEqual(OSPFPacketType.LinkStateRequest, this.lsrPacket.Type);
            Assert.AreEqual(0x7595, this.lsrPacket.Checksum);
            Assert.AreEqual(this.lsrPacket is OSPFv2LSRequestPacket, true);
            lp = (OSPFv2LSRequestPacket) this.lsrPacket;
            Assert.AreEqual(7, lp.LinkStateRequests.Count);
        }

        [Test]
        public void TestLSUConstruction()
        {
            RouterLSA rl;
            NetworkLSA nl;
            SummaryLSA sl;
            ASExternalLSA al;

            //test ctor 1
            OSPFv2LSUpdatePacket p = new OSPFv2LSUpdatePacket
            {
                RouterID = IPAddress.Parse("192.168.255.255"),
                AreaID = IPAddress.Parse("192.168.255.252")
            };

            Assert.AreEqual(OSPFVersion.OSPFv2, p.Version);
            Assert.AreEqual(OSPFPacketType.LinkStateUpdate, p.Type);

            Assert.AreEqual(IPAddress.Parse("192.168.255.255"), p.RouterID);
            Assert.AreEqual(IPAddress.Parse("192.168.255.252"), p.AreaID);

            Assert.AreEqual(0, p.LSANumber);

            //test re-creation
            Byte[] bytes = p.Bytes;
            OSPFv2LSUpdatePacket lp = new OSPFv2LSUpdatePacket(new ByteArraySegment(bytes));

            Assert.AreEqual(OSPFVersion.OSPFv2, lp.Version);
            Assert.AreEqual(OSPFPacketType.LinkStateUpdate, lp.Type);

            Assert.AreEqual(IPAddress.Parse("192.168.255.255"), lp.RouterID);
            Assert.AreEqual(IPAddress.Parse("192.168.255.252"), lp.AreaID);
            Assert.AreEqual(0, p.LSANumber);

            //ctor 2
            //add routerer LSA
            List<RouterLink> rlist = new List<RouterLink>();

            RouterLink rlink = new RouterLink
            {
                Type = 3,
                LinkID = IPAddress.Parse("192.168.20.0"),
                LinkData = IPAddress.Parse("255.255.255.0"),
                TOSNumber = 0,
                Metric = 10
            };
            rlist.Add(rlink);

            rlink = new RouterLink
            {
                Type = 2,
                LinkID = IPAddress.Parse("10.0.20.2"),
                LinkData = IPAddress.Parse("10.0.20.2"),
                TOSNumber = 0,
                Metric = 10
            };
            rlist.Add(rlink);
            rl = new RouterLSA(rlist)
            {
                LSAge = 446,
                Options = 0x22,
                LinkStateID = IPAddress.Parse("5.5.5.5"),
                AdvertisingRouter = IPAddress.Parse("5.5.5.5"),
                LSSequenceNumber = 0x80000004,
                Checksum = 0x7caa,
                VBit = 0,
                EBit = 0,
                BBit = 0
            };

            //add network lsa
            List<IPAddress> rtrs = new List<IPAddress>
            {
                IPAddress.Parse("5.5.5.5"),
                IPAddress.Parse("4.4.4.4")
            };

            nl = new NetworkLSA(rtrs)
            {
                LSAge = 446,
                Options = 0x22,
                LSType = LSAType.Network,
                LinkStateID = IPAddress.Parse("10.0.20.2"),
                AdvertisingRouter = IPAddress.Parse("5.5.5.5"),
                LSSequenceNumber = 0x80000001,
                Checksum = 0xf6ed,
                NetworkMask = IPAddress.Parse("255.255.255.252")
            };

            //add summary lsa
            List<TOSMetric> tms = new List<TOSMetric>();

            TOSMetric tm = new TOSMetric
            {
                TOS = 1,
                Metric = 11
            };
            tms.Add(tm);

            tm = new TOSMetric
            {
                TOS = 2,
                Metric = 22
            };
            tms.Add(tm);

            sl = new SummaryLSA(tms)
            {
                LSAge = 11,
                Options = 0x22,
                LSType = LSAType.Summary,
                LinkStateID = IPAddress.Parse("192.168.10.0"),
                AdvertisingRouter = IPAddress.Parse("4.4.4.4"),
                LSSequenceNumber = 0x80000001,
                Checksum = 0x1e7d,
                NetworkMask = IPAddress.Parse("255.255.255.0"),
                Metric = 30
            };

            //add AS External LSA
            ASExternalLink aslink = new ASExternalLink
            {
                EBit = 1,
                Metric = 100,
                ExternalRouteTag = 0,
                TOS = 0,
                ForwardingAddress = IPAddress.Parse("0.0.0.0")
            };

            List<ASExternalLink> links = new List<ASExternalLink>
            {
                aslink
            };

            al = new ASExternalLSA(links)
            {
                LSAge = 197,
                Options = 0x20,
                LSType = LSAType.ASExternal,
                LinkStateID = IPAddress.Parse("172.16.2.0"),
                AdvertisingRouter = IPAddress.Parse("2.2.2.2"),
                LSSequenceNumber = 0x80000001,
                Checksum = 0x3356,
                NetworkMask = IPAddress.Parse("255.255.255.0")
            };

            //put them all together in a list
            List<LSA> lsas = new List<LSA>
            {
                rl,
                nl,
                sl,
                al
            };

            p = new OSPFv2LSUpdatePacket(lsas)
            {
                RouterID = IPAddress.Parse("192.168.255.255"),
                AreaID = IPAddress.Parse("192.168.255.252")
            };

            Assert.AreEqual(OSPFVersion.OSPFv2, p.Version);
            Assert.AreEqual(OSPFPacketType.LinkStateUpdate, p.Type);

            Assert.AreEqual(IPAddress.Parse("192.168.255.255"), p.RouterID);
            Assert.AreEqual(IPAddress.Parse("192.168.255.252"), p.AreaID);

            Assert.AreEqual(4, p.LSANumber);


            //test router lsa
            rl = (RouterLSA) p.LSAUpdates[0];
            Assert.AreEqual(446, rl.LSAge);
            Assert.AreEqual(0x22, rl.Options);
            Assert.AreEqual(LSAType.Router, rl.LSType);
            Assert.AreEqual(IPAddress.Parse("5.5.5.5"), rl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("5.5.5.5"), rl.AdvertisingRouter);
            Assert.AreEqual(0x80000004, rl.LSSequenceNumber);
            Assert.AreEqual(0x7caa, rl.Checksum);
            Assert.AreEqual(48, rl.Length);
            Assert.AreEqual(0, rl.VBit);
            Assert.AreEqual(0, rl.EBit);
            Assert.AreEqual(0, rl.BBit);
            Assert.AreEqual(2, rl.RouterLinks.Count);

            rlink = rl.RouterLinks[0];
            Assert.AreEqual(3, rlink.Type);
            Assert.AreEqual(IPAddress.Parse("192.168.20.0"), rlink.LinkID);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), rlink.LinkData);
            Assert.AreEqual(0, rlink.TOSNumber);
            Assert.AreEqual(10, rlink.Metric);

            rlink = rl.RouterLinks[1];
            Assert.AreEqual(2, rlink.Type);
            Assert.AreEqual(IPAddress.Parse("10.0.20.2"), rlink.LinkID);
            Assert.AreEqual(IPAddress.Parse("10.0.20.2"), rlink.LinkData);
            Assert.AreEqual(0, rlink.TOSNumber);
            Assert.AreEqual(10, rlink.Metric);

            //test network lsa
            nl = (NetworkLSA) p.LSAUpdates[1];
            Assert.AreEqual(446, nl.LSAge);
            Assert.AreEqual(0x22, nl.Options);
            Assert.AreEqual(LSAType.Network, nl.LSType);
            Assert.AreEqual(IPAddress.Parse("10.0.20.2"), nl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("5.5.5.5"), nl.AdvertisingRouter);
            Assert.AreEqual(0x80000001, nl.LSSequenceNumber);
            Assert.AreEqual(0xf6ed, nl.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.252"), nl.NetworkMask);
            Assert.AreEqual(IPAddress.Parse("5.5.5.5"), nl.AttachedRouters[0]);
            Assert.AreEqual(IPAddress.Parse("4.4.4.4"), nl.AttachedRouters[1]);
            Assert.AreEqual(32, nl.Length);

            //test summary lsa
            sl = (SummaryLSA) p.LSAUpdates[2];
            Assert.AreEqual(11, sl.LSAge);
            Assert.AreEqual(0x22, sl.Options);
            Assert.AreEqual(LSAType.Summary, sl.LSType);
            Assert.AreEqual(IPAddress.Parse("192.168.10.0"), sl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("4.4.4.4"), sl.AdvertisingRouter);
            Assert.AreEqual(0x80000001, sl.LSSequenceNumber);
            Assert.AreEqual(0x1e7d, sl.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), sl.NetworkMask);
            Assert.AreEqual(30, sl.Metric);
            Assert.AreEqual(36, sl.Length);
            Assert.AreEqual(2, sl.TOSMetrics.Count);

            Assert.AreEqual(1, sl.TOSMetrics[0].TOS);
            Assert.AreEqual(11, sl.TOSMetrics[0].Metric);
            Assert.AreEqual(2, sl.TOSMetrics[1].TOS);
            Assert.AreEqual(22, sl.TOSMetrics[1].Metric);

            //test AS-External-LSA
            al = (ASExternalLSA) p.LSAUpdates[3];
            Assert.AreEqual(197, al.LSAge);
            Assert.AreEqual(0x20, al.Options);
            Assert.AreEqual(LSAType.ASExternal, al.LSType);
            Assert.AreEqual(IPAddress.Parse("172.16.2.0"), al.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("2.2.2.2"), al.AdvertisingRouter);
            Assert.AreEqual(0x80000001, al.LSSequenceNumber);
            Assert.AreEqual(0x3356, al.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), al.NetworkMask);
            Assert.AreEqual(1, al.ASExternalLinks.Count);
            Assert.AreEqual(36, al.Length);

            aslink = al.ASExternalLinks[0];
            Assert.AreEqual(1, aslink.EBit);
            Assert.AreEqual(100, aslink.Metric);
            Assert.AreEqual(0, aslink.ExternalRouteTag);
            Assert.AreEqual(0, aslink.TOS);
            Assert.AreEqual(IPAddress.Parse("0.0.0.0"), aslink.ForwardingAddress);
        }

        [Test]
        public void TestLSUPacket()
        {
            OSPFv2LSUpdatePacket lp = null;
            Assert.IsNotNull(this.lsuPacket);
            Assert.AreEqual(OSPFVersion.OSPFv2, this.lsuPacket.Version);
            Assert.AreEqual(OSPFPacketType.LinkStateUpdate, this.lsuPacket.Type);
            Assert.AreEqual(0x961f, this.lsuPacket.Checksum);
            Assert.AreEqual(this.lsuPacket is OSPFv2LSUpdatePacket, true);
            lp = (OSPFv2LSUpdatePacket) this.lsuPacket;
            Assert.AreEqual(1, lp.LSANumber);
            List<LSA> l = lp.LSAUpdates;
            Assert.AreEqual(1, l.Count);
            Assert.AreEqual(typeof(RouterLSA), l[0].GetType());
            Console.WriteLine(l[0]);
        }

        [Test]
        public void TestNetworkLSACreation()
        {
            //ctor 1
            NetworkLSA nl = new NetworkLSA
            {
                LSAge = 333,
                Options = 0x20,
                LSType = LSAType.Network,
                LinkStateID = IPAddress.Parse("1.1.1.1"),
                AdvertisingRouter = IPAddress.Parse("2.2.2.2"),
                LSSequenceNumber = 0x8000000F,
                Checksum = 0xdede,
                NetworkMask = IPAddress.Parse("255.255.255.252")
            };

            Assert.AreEqual(333, nl.LSAge);
            Assert.AreEqual(0x20, nl.Options);
            Assert.AreEqual(LSAType.Network, nl.LSType);
            Assert.AreEqual(IPAddress.Parse("1.1.1.1"), nl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("2.2.2.2"), nl.AdvertisingRouter);
            Assert.AreEqual(0x8000000F, nl.LSSequenceNumber);
            Assert.AreEqual(0xdede, nl.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.252"), nl.NetworkMask);
            Assert.AreEqual(24, nl.Length);

            //ctor 2
            List<IPAddress> rtrs = new List<IPAddress>
            {
                IPAddress.Parse("5.5.5.5"),
                IPAddress.Parse("4.4.4.4")
            };

            nl = new NetworkLSA(rtrs)
            {
                LSAge = 446,
                Options = 0x22,
                LSType = LSAType.Network,
                LinkStateID = IPAddress.Parse("10.0.20.2"),
                AdvertisingRouter = IPAddress.Parse("5.5.5.5"),
                LSSequenceNumber = 0x80000001,
                Checksum = 0xf6ed,
                NetworkMask = IPAddress.Parse("255.255.255.252")
            };

            Assert.AreEqual(446, nl.LSAge);
            Assert.AreEqual(0x22, nl.Options);
            Assert.AreEqual(LSAType.Network, nl.LSType);
            Assert.AreEqual(IPAddress.Parse("10.0.20.2"), nl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("5.5.5.5"), nl.AdvertisingRouter);
            Assert.AreEqual(0x80000001, nl.LSSequenceNumber);
            Assert.AreEqual(0xf6ed, nl.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.252"), nl.NetworkMask);
            Assert.AreEqual(IPAddress.Parse("5.5.5.5"), nl.AttachedRouters[0]);
            Assert.AreEqual(IPAddress.Parse("4.4.4.4"), nl.AttachedRouters[1]);
            Assert.AreEqual(32, nl.Length);
        }

        [Test]
        public void TestOSPFv2Auth()
        {
            RawCapture raw;
            var dev = new CaptureFileReaderDevice("../../CaptureFiles/ospfv2_md5.pcap");
            OSPFv2HelloPacket[] testSubjects = new OSPFv2HelloPacket[4];
            Int32 i = 0;

            dev.Open();
            while ((raw = dev.GetNextPacket()) != null && i < 4)
            {
                testSubjects[i] = (OSPFv2HelloPacket) Packet.ParsePacket(raw.LinkLayerType, raw.Data)
                    .Extract(typeof(OSPFv2HelloPacket));
                i++;
            }

            dev.Close();

            Assert.AreEqual(testSubjects[0].Authentication, 0x000000103c7ec4f7);
            Assert.AreEqual(testSubjects[1].Authentication, 0x000000103c7ec4fc);
            Assert.AreEqual(testSubjects[2].Authentication, 0x000000103c7ec501);
            Assert.AreEqual(testSubjects[3].Authentication, 0x000000103c7ec505);
            Assert.AreEqual(0, testSubjects[0].NeighborID.Count);
            Assert.AreEqual(0, testSubjects[1].NeighborID.Count);
            Assert.AreEqual(1, testSubjects[2].NeighborID.Count);
            Assert.AreEqual(1, testSubjects[3].NeighborID.Count);
            Assert.AreEqual(IPAddress.Parse("10.0.0.2"), testSubjects[2].NeighborID[0]);
            Assert.AreEqual(IPAddress.Parse("10.0.0.1"), testSubjects[3].NeighborID[0]);
        }

        [Test]
        public void TestRouterLSAConstruction()
        {
            //ctor 1
            RouterLSA rl = new RouterLSA
            {
                LSAge = 333,
                Options = 0x20,
                LinkStateID = IPAddress.Parse("1.1.1.1"),
                AdvertisingRouter = IPAddress.Parse("2.2.2.2"),
                LSSequenceNumber = 0x80000001,
                Checksum = 0xaaaa,
                VBit = 1,
                EBit = 0,
                BBit = 1
            };


            Assert.AreEqual(333, rl.LSAge);
            Assert.AreEqual(0x20, rl.Options);
            Assert.AreEqual(LSAType.Router, rl.LSType);
            Assert.AreEqual(IPAddress.Parse("1.1.1.1"), rl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("2.2.2.2"), rl.AdvertisingRouter);
            Assert.AreEqual(0x80000001, rl.LSSequenceNumber);
            Assert.AreEqual(0xaaaa, rl.Checksum);
            Assert.AreEqual(24, rl.Length);
            Assert.AreEqual(1, rl.VBit);
            Assert.AreEqual(0, rl.EBit);
            Assert.AreEqual(1, rl.BBit);
            Assert.AreEqual(0, rl.RouterLinks.Count);

            List<RouterLink> rlist = new List<RouterLink>();

            RouterLink rlink = new RouterLink
            {
                Type = 3,
                LinkID = IPAddress.Parse("192.168.20.0"),
                LinkData = IPAddress.Parse("255.255.255.0"),
                TOSNumber = 0,
                Metric = 10
            };
            rlist.Add(rlink);

            rlink = new RouterLink
            {
                Type = 2,
                LinkID = IPAddress.Parse("10.0.20.2"),
                LinkData = IPAddress.Parse("10.0.20.2"),
                TOSNumber = 0,
                Metric = 10
            };
            rlist.Add(rlink);

            //ctor 2
            rl = new RouterLSA(rlist)
            {
                LSAge = 446,
                Options = 0x22,
                LinkStateID = IPAddress.Parse("5.5.5.5"),
                AdvertisingRouter = IPAddress.Parse("5.5.5.5"),
                LSSequenceNumber = 0x80000004,
                Checksum = 0x7caa,
                VBit = 0,
                EBit = 0,
                BBit = 0
            };

            Assert.AreEqual(446, rl.LSAge);
            Assert.AreEqual(0x22, rl.Options);
            Assert.AreEqual(LSAType.Router, rl.LSType);
            Assert.AreEqual(IPAddress.Parse("5.5.5.5"), rl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("5.5.5.5"), rl.AdvertisingRouter);
            Assert.AreEqual(0x80000004, rl.LSSequenceNumber);
            Assert.AreEqual(0x7caa, rl.Checksum);
            Assert.AreEqual(48, rl.Length);
            Assert.AreEqual(0, rl.VBit);
            Assert.AreEqual(0, rl.EBit);
            Assert.AreEqual(0, rl.BBit);
            Assert.AreEqual(2, rl.RouterLinks.Count);

            rlink = rl.RouterLinks[0];
            Assert.AreEqual(3, rlink.Type);
            Assert.AreEqual(IPAddress.Parse("192.168.20.0"), rlink.LinkID);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), rlink.LinkData);
            Assert.AreEqual(0, rlink.TOSNumber);
            Assert.AreEqual(10, rlink.Metric);

            rlink = rl.RouterLinks[1];
            Assert.AreEqual(2, rlink.Type);
            Assert.AreEqual(IPAddress.Parse("10.0.20.2"), rlink.LinkID);
            Assert.AreEqual(IPAddress.Parse("10.0.20.2"), rlink.LinkData);
            Assert.AreEqual(0, rlink.TOSNumber);
            Assert.AreEqual(10, rlink.Metric);

            //re-creation
        }

        [Test]
        public void TestSummaryLSAConstruction()
        {
            //ctor 1
            SummaryLSA sl = new SummaryLSA
            {
                LSAge = 22,
                Options = 0x20,
                LSType = LSAType.Summary,
                LinkStateID = IPAddress.Parse("1.1.1.1"),
                AdvertisingRouter = IPAddress.Parse("4.4.4.4"),
                LSSequenceNumber = 0x8000000F,
                Checksum = 0xdddd,
                NetworkMask = IPAddress.Parse("255.255.255.0"),
                Metric = 10
            };

            Assert.AreEqual(22, sl.LSAge);
            Assert.AreEqual(0x20, sl.Options);
            Assert.AreEqual(LSAType.Summary, sl.LSType);
            Assert.AreEqual(IPAddress.Parse("1.1.1.1"), sl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("4.4.4.4"), sl.AdvertisingRouter);
            Assert.AreEqual(0x8000000F, sl.LSSequenceNumber);
            Assert.AreEqual(0xdddd, sl.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), sl.NetworkMask);
            Assert.AreEqual(10, sl.Metric);
            Assert.AreEqual(28, sl.Length);
            Assert.AreEqual(0, sl.TOSMetrics.Count);

            List<TOSMetric> tms = new List<TOSMetric>();

            TOSMetric tm = new TOSMetric
            {
                TOS = 1,
                Metric = 11
            };
            tms.Add(tm);

            tm = new TOSMetric
            {
                TOS = 2,
                Metric = 22
            };
            tms.Add(tm);

            //ctor 2
            sl = new SummaryLSA(tms)
            {
                LSAge = 11,
                Options = 0x22,
                LSType = LSAType.Summary,
                LinkStateID = IPAddress.Parse("192.168.10.0"),
                AdvertisingRouter = IPAddress.Parse("4.4.4.4"),
                LSSequenceNumber = 0x80000001,
                Checksum = 0x1e7d,
                NetworkMask = IPAddress.Parse("255.255.255.0"),
                Metric = 30
            };

            Assert.AreEqual(11, sl.LSAge);
            Assert.AreEqual(0x22, sl.Options);
            Assert.AreEqual(LSAType.Summary, sl.LSType);
            Assert.AreEqual(IPAddress.Parse("192.168.10.0"), sl.LinkStateID);
            Assert.AreEqual(IPAddress.Parse("4.4.4.4"), sl.AdvertisingRouter);
            Assert.AreEqual(0x80000001, sl.LSSequenceNumber);
            Assert.AreEqual(0x1e7d, sl.Checksum);
            Assert.AreEqual(IPAddress.Parse("255.255.255.0"), sl.NetworkMask);
            Assert.AreEqual(30, sl.Metric);
            Assert.AreEqual(36, sl.Length);
            Assert.AreEqual(2, sl.TOSMetrics.Count);

            Assert.AreEqual(1, sl.TOSMetrics[0].TOS);
            Assert.AreEqual(11, sl.TOSMetrics[0].Metric);
            Assert.AreEqual(2, sl.TOSMetrics[1].TOS);
            Assert.AreEqual(22, sl.TOSMetrics[1].Metric);
        }
    }
}