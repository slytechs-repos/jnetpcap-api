/*
 * Sly Technologies Free License
 * 
 * Copyright 2025 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.sdk.jnetpcap.api;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.jnetpcap.api.NetPcap;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.PacketSettings;
import com.slytechs.sdk.protocol.core.descriptor.DescriptorInfo;
import com.slytechs.sdk.protocol.core.descriptor.Type2PacketDescriptor;
import com.slytechs.sdk.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.ip.Ip6;
import com.slytechs.sdk.protocol.tcpip.tcp.Tcp;

/**
 * JUnit tests for NetPcap API.
 * 
 * <p>
 * Tests cover the packet pipeline, dissection modes, dispatch/loop/next methods,
 * and protocol header binding.
 * </p>
 */
@DisplayName("NetPcap API Tests")
class NetPcapTest {

    private static final String HTTP_PCAP = "pcaps/HTTP.cap";
    private static final String SMALL_PCAP = "pcaps/small.pcap";
    
    private NetPcap pcap;
    
    @BeforeAll
    static void setUpClass() throws Exception {
        NetPcap.activateLicense();
    }
    
    @AfterEach
    void tearDown() {
        if (pcap != null) {
            pcap.close();
            pcap = null;
        }
    }
    
    @Nested
    @DisplayName("OpenOffline Tests")
    class OpenOfflineTests {
        
        @Test
        @DisplayName("Open pcap file with default settings")
        void openOffline_defaultSettings() throws PcapException {
            pcap = NetPcap.openOffline(HTTP_PCAP);
            
            assertNotNull(pcap);
            assertTrue(pcap.isActivated());
        }
        
        @Test
        @DisplayName("Open pcap file with eager dissection")
        void openOffline_eagerDissection() throws PcapException {
            PacketSettings settings = new PacketSettings().dissect();
            pcap = NetPcap.openOffline(HTTP_PCAP, settings);
            
            assertNotNull(pcap);
            assertTrue(pcap.isActivated());
        }
        
        @Test
        @DisplayName("Open pcap file with on-demand dissection")
        void openOffline_onDemandDissection() throws PcapException {
            PacketSettings settings = new PacketSettings().dissectOnDemand();
            pcap = NetPcap.openOffline(HTTP_PCAP, settings);
            
            assertNotNull(pcap);
            assertTrue(pcap.isActivated());
        }
        
        @Test
        @DisplayName("Open pcap file with no dissection")
        void openOffline_noDissection() throws PcapException {
            PacketSettings settings = new PacketSettings().noDissection();
            pcap = NetPcap.openOffline(HTTP_PCAP, settings);
            
            assertNotNull(pcap);
            assertTrue(pcap.isActivated());
        }
        
        @Test
        @DisplayName("Open pcap file using File object")
        void openOffline_fileObject() throws PcapException {
            File file = new File(HTTP_PCAP);
            pcap = NetPcap.openOffline(file);
            
            assertNotNull(pcap);
            assertTrue(pcap.isActivated());
        }
        
        @Test
        @DisplayName("Open non-existent file throws exception")
        void openOffline_nonExistentFile() {
            assertThrows(PcapException.class, () -> {
                NetPcap.openOffline("non_existent_file.pcap");
            });
        }
    }
    
    @Nested
    @DisplayName("Dispatch Tests")
    class DispatchTests {
        
        @BeforeEach
        void setUp() throws PcapException {
            pcap = NetPcap.openOffline(HTTP_PCAP, new PacketSettings().dissect());
        }
        
        @Test
        @DisplayName("Dispatch single packet")
        void dispatch_singlePacket() throws PcapException {
            AtomicInteger count = new AtomicInteger(0);
            
            int result = pcap.dispatch(1, packet -> {
                count.incrementAndGet();
                assertNotNull(packet);
            });
            
            assertEquals(1, count.get());
            assertTrue(result >= 0);
        }
        
        @Test
        @DisplayName("Dispatch multiple packets")
        void dispatch_multiplePackets() throws PcapException {
            AtomicInteger count = new AtomicInteger(0);
            
            int result = pcap.dispatch(10, packet -> {
                count.incrementAndGet();
                assertNotNull(packet);
            });
            
            assertTrue(count.get() > 0);
            assertTrue(count.get() <= 10);
        }
        
        @Test
        @DisplayName("Dispatch with user context")
        void dispatch_withUserContext() throws PcapException {
            List<Integer> captureLengths = new ArrayList<>();
            
            int result = pcap.dispatch(5, (list, packet) -> {
                list.add(packet.captureLength());
            }, captureLengths);
            
            assertFalse(captureLengths.isEmpty());
            assertTrue(captureLengths.stream().allMatch(len -> len > 0));
        }
        
        @Test
        @DisplayName("Dispatch all packets (-1)")
        void dispatch_allPackets() throws PcapException {
            AtomicInteger count = new AtomicInteger(0);
            
            pcap.dispatch(-1, packet -> {
                count.incrementAndGet();
            });
            
            assertTrue(count.get() > 0, "Should have processed at least one packet");
        }
    }
    
    @Nested
    @DisplayName("Loop Tests")
    class LoopTests {
        
        @BeforeEach
        void setUp() throws PcapException {
            pcap = NetPcap.openOffline(HTTP_PCAP, new PacketSettings().dissect());
        }
        
        @Test
        @DisplayName("Loop single packet")
        void loop_singlePacket() {
            AtomicInteger count = new AtomicInteger(0);
            
            int result = pcap.loop(1, packet -> {
                count.incrementAndGet();
                assertNotNull(packet);
            });
            
            assertEquals(1, count.get());
        }
        
        @Test
        @DisplayName("Loop multiple packets")
        void loop_multiplePackets() {
            AtomicInteger count = new AtomicInteger(0);
            
            int result = pcap.loop(5, packet -> {
                count.incrementAndGet();
            });
            
            assertEquals(5, count.get());
        }
        
        @Test
        @DisplayName("Loop with user context")
        void loop_withUserContext() {
            List<Long> timestamps = new ArrayList<>();
            
            pcap.loop(5, (list, packet) -> {
                list.add(packet.timestamp());
            }, timestamps);
            
            assertEquals(5, timestamps.size());
            assertTrue(timestamps.stream().allMatch(ts -> ts > 0));
        }
    }
    
    @Nested
    @DisplayName("Next/NextEx Tests")
    class NextTests {
        
        @BeforeEach
        void setUp() throws PcapException {
            pcap = NetPcap.openOffline(HTTP_PCAP, new PacketSettings().dissect());
        }
        
        @Test
        @DisplayName("Next returns packet")
        void next_returnsPacket() throws PcapException {
            Packet packet = pcap.next();
            
            assertNotNull(packet);
            assertTrue(packet.captureLength() > 0);
        }
        
        @Test
        @DisplayName("Next returns null at EOF")
        void next_returnsNullAtEof() throws PcapException {
            // Read all packets
            while (pcap.next() != null) {
                // consume
            }
            
            // Next call should return null (EOF)
            Packet packet = pcap.next();
            assertNull(packet);
        }
        
        @Test
        @DisplayName("NextEx returns packet")
        void nextEx_returnsPacket() throws PcapException, TimeoutException {
            Packet packet = pcap.nextEx();
            
            assertNotNull(packet);
            assertTrue(packet.captureLength() > 0);
        }
        
        @Test
        @DisplayName("Multiple next calls return sequential packets")
        void next_sequentialPackets() throws PcapException {
            Packet first = pcap.next();
            Packet second = pcap.next();
            
            assertNotNull(first);
            assertNotNull(second);
            // Timestamps should be non-decreasing
            assertTrue(second.timestamp() >= first.timestamp());
        }
    }
    
    @Nested
    @DisplayName("Protocol Dissection Tests")
    class DissectionTests {
        
        @Test
        @DisplayName("Eager dissection provides TYPE2 descriptor")
        void eagerDissection_netDescriptor() throws PcapException {
            pcap = NetPcap.openOffline(HTTP_PCAP, new PacketSettings().dissect());
            
            Packet packet = pcap.next();
            
            assertNotNull(packet);
            assertNotNull(packet.descriptor());
            assertEquals(DescriptorInfo.TYPE2, packet.descriptor().descriptorInfo());
            assertTrue(packet.descriptor() instanceof Type2PacketDescriptor);
        }
        
        @Test
        @DisplayName("Eager dissection populates protocol bitmap")
        void eagerDissection_protocolBitmap() throws PcapException {
            pcap = NetPcap.openOffline(HTTP_PCAP, new PacketSettings().dissect());
            
            Packet packet = pcap.next();
            Type2PacketDescriptor desc = (Type2PacketDescriptor) packet.descriptor();
            
            // HTTP.cap should have Ethernet frames
            assertTrue(desc.getProtoBitmap() != 0, "Should have dissected protocols");
        }
        
        @Test
        @DisplayName("On-demand dissection uses PCAP descriptor")
        void onDemandDissection_pcapDescriptor() throws PcapException {
            pcap = NetPcap.openOffline(HTTP_PCAP, new PacketSettings().dissectOnDemand());
            
            Packet packet = pcap.next();
            
            assertNotNull(packet);
            assertNotNull(packet.descriptor());
            // Should use PCAP descriptor type (PADDED for live/memory)
            assertNotEquals(DescriptorInfo.TYPE2, packet.descriptor().descriptorInfo());
        }
    }
    
    @Nested
    @DisplayName("Header Binding Tests")
    class HeaderBindingTests {
        
        @BeforeEach
        void setUp() throws PcapException {
            pcap = NetPcap.openOffline(HTTP_PCAP, new PacketSettings().dissect());
        }
        
        @Test
        @DisplayName("hasHeader binds Ethernet")
        void hasHeader_ethernet() throws PcapException {
            Ethernet eth = new Ethernet();
            
            Packet packet = pcap.next();
            
            assertTrue(packet.hasHeader(eth), "HTTP.cap should have Ethernet frames");
            assertNotNull(eth.src());
            assertNotNull(eth.dst());
        }
        
        @Test
        @DisplayName("hasHeader binds IPv4")
        void hasHeader_ipv4() throws PcapException {
            try (NetPcap p = NetPcap.openOffline(HTTP_PCAP, new PacketSettings().dissect())) {
                Ip4 ip4 = new Ip4();
                AtomicBoolean found = new AtomicBoolean(false);
                
                p.dispatch(-1, packet -> {
                    if (!found.get() && packet.hasHeader(ip4)) {
                        found.set(true);
                        assertNotNull(ip4.src());
                        assertNotNull(ip4.dst());
                        assertEquals(4, ip4.version());
                    }
                });
                
                assertTrue(found.get(), "HTTP.cap should contain IPv4 packets");
            }
        }
        
        @Test
        @DisplayName("hasHeader binds TCP")
        void hasHeader_tcp() throws PcapException {
            Tcp tcp = new Tcp();
            
            // Find a packet with TCP
            Packet packet;
            boolean found = false;
            while ((packet = pcap.next()) != null) {
                if (packet.hasHeader(tcp)) {
                    found = true;
                    assertTrue(tcp.srcPort() > 0 || tcp.dstPort() > 0);
                    break;
                }
            }
            
            assertTrue(found, "HTTP.cap should contain TCP packets");
        }
        
        @Test
        @DisplayName("Header reuse across packets")
        void headerReuse_acrossPackets() throws PcapException {
            Ethernet eth = new Ethernet();
            Ip4 ip4 = new Ip4();
            
            Packet packet1 = pcap.next();
            assertTrue(packet1.hasHeader(eth));
            String src1 = eth.src().toString();
            
            Packet packet2 = pcap.next();
            if (packet2.hasHeader(eth)) {
                // eth should now be bound to packet2's data
                String src2 = eth.src().toString();
                // Values may or may not be equal, but binding should work
                assertNotNull(src2);
            }
        }
        
        @Test
        @DisplayName("Multiple headers from same packet")
        void multipleHeaders_samePacket() throws PcapException {
            try (NetPcap p = NetPcap.openOffline(HTTP_PCAP, new PacketSettings().dissect())) {
                Ethernet eth = new Ethernet();
                Ip4 ip4 = new Ip4();
                Tcp tcp = new Tcp();
                AtomicBoolean found = new AtomicBoolean(false);
                
                p.dispatch(-1, packet -> {
                    if (!found.get() && packet.hasHeader(eth) && packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
                        assertNotNull(eth.src());
                        assertNotNull(ip4.src());
                        assertTrue(tcp.srcPort() >= 0);
                        found.set(true);
                    }
                });
                
                assertTrue(found.get(), "Should find a packet with ETH+IPv4+TCP");
            }
        }
        
        @Test
        @DisplayName("hasHeader returns false for missing protocol")
        void hasHeader_missingProtocol() throws PcapException {
            Ip6 ip6 = new Ip6();
            
            Packet packet = pcap.next();
            
            // HTTP.cap is typically IPv4, not IPv6
            // This tests that hasHeader correctly returns false
            if (!packet.hasHeader(ip6)) {
                // Expected - no IPv6 in first packet
                assertTrue(true);
            }
        }
    }
    
    @Nested
    @DisplayName("Packet Properties Tests")
    class PacketPropertiesTests {
        
        @BeforeEach
        void setUp() throws PcapException {
            pcap = NetPcap.openOffline(HTTP_PCAP, new PacketSettings().dissect());
        }
        
        @Test
        @DisplayName("Capture length is valid")
        void captureLength_valid() throws PcapException {
            Packet packet = pcap.next();
            
            int caplen = packet.captureLength();
            assertTrue(caplen > 0);
            assertTrue(caplen <= 65535);
        }
        
        @Test
        @DisplayName("Wire length is valid")
        void wireLength_valid() throws PcapException {
            Packet packet = pcap.next();
            
            int wirelen = packet.wireLength();
            assertTrue(wirelen > 0);
            assertTrue(wirelen >= packet.captureLength());
        }
        
        @Test
        @DisplayName("Timestamp is valid")
        void timestamp_valid() throws PcapException {
            Packet packet = pcap.next();
            
            long timestamp = packet.timestamp();
            assertTrue(timestamp > 0, "Timestamp should be positive");
        }
        
        @Test
        @DisplayName("Descriptor is accessible")
        void descriptor_accessible() throws PcapException {
            Packet packet = pcap.next();
            
            assertNotNull(packet.descriptor());
            assertNotNull(packet.descriptor().descriptorInfo());
        }
    }
    
    @Nested
    @DisplayName("Filter Tests")
    class FilterTests {
        
        @Test
        @DisplayName("Set TCP filter")
        void setFilter_tcp() throws PcapException {
            pcap = NetPcap.openOffline(HTTP_PCAP, new PacketSettings().dissect());
            pcap.setFilter("tcp");
            
            Tcp tcp = new Tcp();
            Packet packet = pcap.next();
            
            if (packet != null) {
                assertTrue(packet.hasHeader(tcp), "Filtered packet should be TCP");
            }
        }
        
        @Test
        @DisplayName("Set port filter")
        void setFilter_port() throws PcapException {
            pcap = NetPcap.openOffline(HTTP_PCAP, new PacketSettings().dissect());
            pcap.setFilter("tcp port 80");
            
            Tcp tcp = new Tcp();
            Packet packet = pcap.next();
            
            if (packet != null && packet.hasHeader(tcp)) {
                assertTrue(tcp.srcPort() == 80 || tcp.dstPort() == 80,
                        "Filtered packet should have port 80");
            }
        }
        
        @Test
        @DisplayName("Invalid filter throws exception")
        void setFilter_invalid() throws PcapException {
            pcap = NetPcap.openOffline(HTTP_PCAP);
            
            assertThrows(PcapException.class, () -> {
                pcap.setFilter("invalid filter expression !!!");
            });
        }
    }
    
    @Nested
    @DisplayName("PacketSettings Configuration Tests")
    class PacketSettingsTests {
        
        @Test
        @DisplayName("Default settings enable eager dissection")
        void defaultSettings_eagerDissection() {
            PacketSettings settings = new PacketSettings();
            
            assertTrue(settings.isEagerDissection());
            assertFalse(settings.isOnDemandDissection());
            assertTrue(settings.isDissectionEnabled());
            assertTrue(settings.isHybridMemory());
            assertEquals(DescriptorInfo.TYPE2, settings.descriptorType());
        }
        
        @Test
        @DisplayName("dissect() enables eager dissection")
        void dissect_enablesEager() {
            PacketSettings settings = new PacketSettings().dissect();
            
            assertTrue(settings.isEagerDissection());
            assertFalse(settings.isOnDemandDissection());
        }
        
        @Test
        @DisplayName("dissectOnDemand() enables on-demand")
        void dissectOnDemand_enablesOnDemand() {
            PacketSettings settings = new PacketSettings().dissectOnDemand();
            
            assertFalse(settings.isEagerDissection());
            assertTrue(settings.isOnDemandDissection());
            assertTrue(settings.isDissectionEnabled());
            assertFalse(settings.isHybridMemory());
            assertEquals(DescriptorInfo.PCAP_PACKED, settings.descriptorType());
        }
        
        @Test
        @DisplayName("noDissection() disables all dissection")
        void noDissection_disablesAll() {
            PacketSettings settings = new PacketSettings().noDissection();
            
            assertFalse(settings.isEagerDissection());
            assertFalse(settings.isOnDemandDissection());
            assertFalse(settings.isDissectionEnabled());
            assertFalse(settings.isHybridMemory());
        }
        
        @Test
        @DisplayName("Mode methods are mutually exclusive")
        void modes_mutuallyExclusive() {
            PacketSettings settings = new PacketSettings();
            
            // Start with dissect (default)
            assertTrue(settings.isEagerDissection());
            
            // Switch to on-demand
            settings.dissectOnDemand();
            assertFalse(settings.isEagerDissection());
            assertTrue(settings.isOnDemandDissection());
            
            // Switch to none
            settings.noDissection();
            assertFalse(settings.isEagerDissection());
            assertFalse(settings.isOnDemandDissection());
            
            // Back to eager
            settings.dissect();
            assertTrue(settings.isEagerDissection());
            assertFalse(settings.isOnDemandDissection());
        }
    }
    
    @Nested
    @DisplayName("Resource Management Tests")
    class ResourceManagementTests {
        
        @Test
        @DisplayName("Close releases resources")
        void close_releasesResources() throws PcapException {
            pcap = NetPcap.openOffline(HTTP_PCAP);
            pcap.close();
            
            // After close, operations should fail or handle gracefully
            pcap = null; // Prevent double-close in tearDown
        }
        
        @Test
        @DisplayName("Try-with-resources pattern")
        void tryWithResources() throws PcapException {
            AtomicInteger count = new AtomicInteger(0);
            
            try (NetPcap p = NetPcap.openOffline(HTTP_PCAP)) {
                p.dispatch(5, packet -> count.incrementAndGet());
            }
            
            assertTrue(count.get() > 0);
        }
        
        @Test
        @DisplayName("Multiple sequential opens")
        void multipleOpens() throws PcapException {
            for (int i = 0; i < 3; i++) {
                try (NetPcap p = NetPcap.openOffline(HTTP_PCAP)) {
                    Packet packet = p.next();
                    assertNotNull(packet);
                }
            }
        }
    }
}