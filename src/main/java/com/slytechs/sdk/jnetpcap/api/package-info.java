/*
 * Apache License, Version 2.0
 * 
 * Copyright 2005-2025 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

/**
 * jNetPcap 3.0 API - High-performance packet capture with protocol dissection.
 * 
 * <p>
 * This package provides {@link NetPcap}, a high-level packet capture interface that
 * wraps the low-level {@link com.slytechs.sdk.jnetpcap.Pcap} bindings and integrates
 * with protocol dissection. Packets delivered through {@code dispatch()}, {@code loop()},
 * {@code next()}, and {@code nextEx()} are fully dissected with protocol headers
 * accessible via the zero-allocation {@code hasHeader()} pattern.
 * </p>
 * 
 * <h2>API Layers</h2>
 * 
 * <p>
 * jNetPcap provides two API layers:
 * </p>
 * 
 * <table>
 * <caption>jNetPcap API Layers</caption>
 * <tr><th>Class</th><th>Package</th><th>Description</th></tr>
 * <tr><td>{@link com.slytechs.sdk.jnetpcap.Pcap}</td><td>sdk-jnetpcap</td>
 *     <td>Low-level libpcap bindings - direct native access</td></tr>
 * <tr><td>{@link NetPcap}</td><td>jnetpcap-api</td>
 *     <td>High-level API with protocol dissection</td></tr>
 * </table>
 * 
 * <h2>Configuration: NetPcap vs PacketSettings</h2>
 * 
 * <p>
 * There are two distinct configuration concerns:
 * </p>
 * 
 * <table>
 * <caption>Configuration Separation</caption>
 * <tr><th>Configuration</th><th>Purpose</th><th>Methods</th></tr>
 * <tr><td>{@link NetPcap} setters</td><td>Capture properties (pcap API)</td>
 *     <td>{@code setSnaplen()}, {@code setTimeout()}, {@code setPromisc()},
 *         {@code setFilter()}, {@code setBufferSize()}, etc.</td></tr>
 * <tr><td>{@link PacketSettings}</td><td>Packet structure &amp; memory</td>
 *     <td>{@code dissect()}, {@code zeroCopy()}, {@code descriptorType()}, etc.</td></tr>
 * </table>
 * 
 * <h3>NetPcap Configuration</h3>
 * <p>
 * NetPcap setters configure traditional pcap capture properties - how packets are
 * captured from the network or read from files:
 * </p>
 * <ul>
 * <li>{@code setSnaplen(int)} - Maximum bytes to capture per packet</li>
 * <li>{@code setTimeout(Duration)} - Read timeout</li>
 * <li>{@code setPromisc(boolean)} - Promiscuous mode</li>
 * <li>{@code setFilter(String)} - BPF filter expression</li>
 * <li>{@code setBufferSize(int)} - Kernel buffer size</li>
 * <li>{@code setImmediateMode(boolean)} - Disable buffering</li>
 * <li>{@code setDirection(PcapDirection)} - Capture direction</li>
 * <li>{@code setTstampType(PcapTstampType)} - Timestamp source</li>
 * <li>{@code setTstampPrecision(PcapTStampPrecision)} - Timestamp precision</li>
 * </ul>
 * 
 * <h3>PacketSettings Configuration</h3>
 * <p>
 * PacketSettings configures how packets are structured and managed in memory:
 * </p>
 * <ul>
 * <li>{@code dissect()} - Enable eager protocol dissection (TYPE2 descriptor)</li>
 * <li>{@code onDemand()} - Enable on-demand dissection</li>
 * <li>{@code zeroCopy()} - Use scoped memory (valid only in callback)</li>
 * <li>{@code descriptorType(DescriptorTypeInfo)} - Choose descriptor format</li>
 * </ul>
 * 
 * <h2>Quick Start</h2>
 * 
 * <h3>Simple Live Capture</h3>
 * <pre>{@code
 * try (NetPcap pcap = NetPcap.openLive("eth0", 65535, true, Duration.ofSeconds(1))) {
 *     Ip4 ip = new Ip4();
 *     
 *     pcap.loop(100, packet -> {
 *         if (packet.hasHeader(ip)) {
 *             System.out.printf("%s -> %s%n", ip.src(), ip.dst());
 *         }
 *     });
 * }
 * }</pre>
 * 
 * <h3>Offline File Reading with PacketSettings</h3>
 * <pre>{@code
 * PacketSettings settings = new PacketSettings()
 *     .dissect();  // Eager dissection with TYPE2 descriptor
 * 
 * try (NetPcap pcap = NetPcap.openOffline("capture.pcap", settings)) {
 *     pcap.setFilter("tcp port 80");
 *     
 *     Packet packet;
 *     while ((packet = pcap.next()) != null) {
 *         // Process dissected packet...
 *     }
 * }
 * }</pre>
 * 
 * <h3>Two-Stage Capture Configuration</h3>
 * <pre>{@code
 * try (NetPcap pcap = NetPcap.create("eth0")) {
 *     // NetPcap configuration (capture properties)
 *     pcap.setSnaplen(128)
 *         .setPromisc(true)
 *         .setTimeout(100)
 *         .setImmediateMode(true)
 *         .activate();
 *     
 *     pcap.dispatch(1000, packet -> {
 *         // Process packet...
 *     });
 * }
 * }</pre>
 * 
 * <h3>Full Configuration Example</h3>
 * <pre>{@code
 * // PacketSettings - packet structure configuration
 * PacketSettings settings = new PacketSettings()
 *     .dissect();  // Eager dissection
 * 
 * try (NetPcap pcap = NetPcap.create("eth0", settings)) {
 *     // NetPcap - capture configuration
 *     pcap.setSnaplen(65535)
 *         .setTimeout(Duration.ofSeconds(1))
 *         .setPromisc(true)
 *         .setBufferSize(16 * 1024 * 1024)
 *         .setTstampPrecision(PcapTStampPrecision.NANO)
 *         .activate();
 *     
 *     pcap.setFilter("tcp port 80 or tcp port 443");
 *     
 *     Ethernet eth = new Ethernet();
 *     Ip4 ip4 = new Ip4();
 *     Tcp tcp = new Tcp();
 *     
 *     pcap.dispatch(1000, packet -> {
 *         if (packet.hasHeader(eth) && packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
 *             System.out.printf("%s:%d -> %s:%d%n",
 *                 ip4.src(), tcp.srcPort(),
 *                 ip4.dst(), tcp.dstPort());
 *         }
 *     });
 * }
 * }</pre>
 * 
 * <h2>Core Components</h2>
 * 
 * <table>
 * <caption>jNetPcap API Classes</caption>
 * <tr><th>Class</th><th>Description</th></tr>
 * <tr><td>{@link NetPcap}</td><td>High-level capture with protocol dissection</td></tr>
 * <tr><td>{@link PacketSettings}</td><td>Packet structure and memory configuration</td></tr>
 * <tr><td>{@link PacketHandler}</td><td>Packet callback interface</td></tr>
 * <tr><td>{@link com.slytechs.sdk.jnetpcap.Pcap}</td><td>Low-level libpcap bindings</td></tr>
 * <tr><td>{@link com.slytechs.sdk.jnetpcap.PcapIf}</td><td>Network interface descriptor</td></tr>
 * <tr><td>{@link com.slytechs.sdk.jnetpcap.BpFilter}</td><td>Compiled BPF filter</td></tr>
 * </table>
 * 
 * <h2>Memory Model</h2>
 * 
 * <p>
 * jNetPcap uses a layered memory model optimized for performance:
 * </p>
 * 
 * <pre>
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                     Native Capture Buffer                       │
 * │  ┌─────────────────────────────────────────────────────────┐    │
 * │  │ Packet 1 │ Packet 2 │ Packet 3 │ ...                    │    │
 * │  └─────────────────────────────────────────────────────────┘    │
 * │       ▲                                                         │
 * │       │ ScopedMemory (zero-copy binding)                        │
 * │       │                                                         │
 * │  ┌────┴────────────────┐                                        │
 * │  │ Packet              │                                        │
 * │  │  ├─ ScopedMemory    │  Data bound to native buffer           │
 * │  │  ├─ Descriptor      │  Protocol dissection results           │
 * │  │  └─ Header bindings │  Zero-allocation header access         │
 * │  └─────────────────────┘                                        │
 * │                                                                 │
 * │  Scope: Valid within dispatch/loop callback only                │
 * └─────────────────────────────────────────────────────────────────┘
 * </pre>
 * 
 * <h3>Memory Types</h3>
 * 
 * <table>
 * <caption>Memory Strategies</caption>
 * <tr><th>Type</th><th>Allocation</th><th>Lifetime</th><th>Use Case</th></tr>
 * <tr><td>ScopedMemory</td><td>None (bind only)</td><td>Callback scope</td><td>Zero-copy capture</td></tr>
 * <tr><td>FixedMemory</td><td>Pool or Arena</td><td>Until recycled</td><td>Persistent packets</td></tr>
 * <tr><td>Hybrid</td><td>Mixed</td><td>Mixed</td><td>Zero-copy data + fixed descriptor</td></tr>
 * </table>
 * 
 * <h2>Protocol Dissection</h2>
 * 
 * <h3>Dissection Modes</h3>
 * 
 * <table>
 * <caption>Dissection Modes (PacketSettings)</caption>
 * <tr><th>Mode</th><th>Method</th><th>Description</th></tr>
 * <tr><td>Eager</td><td>{@code dissect()}</td><td>Full dissection before callback, TYPE2 descriptor</td></tr>
 * <tr><td>On-demand</td><td>{@code onDemand()}</td><td>Dissect lazily on first {@code hasHeader()}</td></tr>
 * <tr><td>None</td><td>(default)</td><td>No dissection, PCAP descriptor only</td></tr>
 * </table>
 * 
 * <h3>Zero-Allocation Header Access</h3>
 * 
 * <p>
 * The {@code hasHeader(Header)} pattern provides zero-allocation protocol access
 * by reusing header instances:
 * </p>
 * 
 * <pre>{@code
 * // Create once, reuse forever (from sdk-protocol-tcpip)
 * Ethernet eth = new Ethernet();
 * Ip4 ip4 = new Ip4();
 * Ip6 ip6 = new Ip6();
 * Tcp tcp = new Tcp();
 * Udp udp = new Udp();
 * 
 * pcap.loop(-1, packet -> {
 *     // hasHeader() binds the header to packet data if present
 *     if (packet.hasHeader(eth)) {
 *         byte[] dstMac = eth.dst();
 *         int etherType = eth.type();
 *     }
 *     
 *     if (packet.hasHeader(ip4)) {
 *         String srcIp = ip4.src();
 *         int ttl = ip4.ttl();
 *     } else if (packet.hasHeader(ip6)) {
 *         String srcIp = ip6.src();
 *         int hopLimit = ip6.hopLimit();
 *     }
 *     
 *     if (packet.hasHeader(tcp)) {
 *         int srcPort = tcp.srcPort();
 *         int dstPort = tcp.dstPort();
 *     }
 * });
 * }</pre>
 * 
 * <h3>Tunneled Protocol Access</h3>
 * 
 * <p>
 * For tunneled packets (GRE, VXLAN, etc.), use depth parameter:
 * </p>
 * 
 * <pre>{@code
 * Ip4 outerIp = new Ip4();
 * Ip4 innerIp = new Ip4();
 * 
 * if (packet.hasHeader(outerIp, 0)) {      // Outer IP (depth 0)
 *     System.out.println("Outer: " + outerIp.src());
 * }
 * if (packet.hasHeader(innerIp, 1)) {      // Inner IP (depth 1)
 *     System.out.println("Inner: " + innerIp.src());
 * }
 * }</pre>
 * 
 * <h2>Packet Persistence</h2>
 * 
 * <p>
 * Packets in callbacks are bound to native buffers and valid only within scope.
 * To keep packets beyond the callback, use the persistence API:
 * </p>
 * 
 * <table>
 * <caption>Persistence Methods</caption>
 * <tr><th>Method</th><th>Returns</th><th>Memory</th><th>Use Case</th></tr>
 * <tr><td>{@code persist()}</td><td>Same or copy</td><td>Fixed</td><td>Keep beyond scope</td></tr>
 * <tr><td>{@code persistTo(target)}</td><td>Same or target</td><td>Target's</td><td>Pooled persistence</td></tr>
 * <tr><td>{@code persistTo(pool)}</td><td>Same or pooled</td><td>Pool</td><td>High-volume</td></tr>
 * <tr><td>{@code copy()}</td><td>New copy</td><td>Auto-managed</td><td>Independent copy</td></tr>
 * <tr><td>{@code copyTo(target)}</td><td>target</td><td>Target's</td><td>Pooled copy</td></tr>
 * <tr><td>{@code duplicate()}</td><td>New object</td><td>Shared (+ref)</td><td>Parallel processing</td></tr>
 * </table>
 * 
 * <pre>{@code
 * Queue<Packet> queue = new ConcurrentLinkedQueue<>();
 * 
 * pcap.loop(-1, packet -> {
 *     if (isInteresting(packet)) {
 *         Packet keeper = packet.persist();
 *         queue.add(keeper);
 *     }
 * });
 * 
 * // Consumer thread
 * while (running) {
 *     Packet p = queue.poll();
 *     if (p != null) {
 *         process(p);
 *         p.recycle();  // Return to pool (no-op if non-pooled)
 *     }
 * }
 * }</pre>
 * 
 * <h2>Berkeley Packet Filter (BPF)</h2>
 * 
 * <pre>{@code
 * try (NetPcap pcap = NetPcap.openLive("eth0")) {
 *     pcap.setFilter("tcp port 80 or tcp port 443");
 *     pcap.loop(-1, handler);
 * }
 * }</pre>
 * 
 * <h3>Common Filter Expressions</h3>
 * 
 * <pre>
 * "tcp"                          - All TCP packets
 * "udp port 53"                  - DNS traffic
 * "host 192.168.1.1"             - Traffic to/from host
 * "net 10.0.0.0/8"               - Traffic to/from network
 * "tcp port 80 or tcp port 443"  - HTTP and HTTPS
 * "icmp"                         - ICMP packets
 * "vlan 100"                     - VLAN tagged
 * "tcp[tcpflags] & tcp-syn != 0" - TCP SYN packets
 * </pre>
 * 
 * <h2>Packet Descriptors</h2>
 * 
 * <table>
 * <caption>Descriptor Types</caption>
 * <tr><th>Type</th><th>Size</th><th>Use Case</th></tr>
 * <tr><td>{@code PCAP_PADDED}</td><td>24 bytes</td><td>Kernel format (x64 padded)</td></tr>
 * <tr><td>{@code PCAP_PACKED}</td><td>16 bytes</td><td>File format (packed)</td></tr>
 * <tr><td>{@code TYPE2}</td><td>96 bytes</td><td>Full protocol dissection</td></tr>
 * </table>
 * 
 * <h2>Thread Safety</h2>
 * 
 * <p>
 * <strong>NetPcap is strictly single-threaded.</strong> All capture operations
 * must occur on the same thread. For multi-threaded processing:
 * </p>
 * 
 * <ul>
 * <li>Capture on dedicated thread</li>
 * <li>Use {@code persist()} for packets leaving capture thread</li>
 * <li>Each thread needs its own header instances</li>
 * </ul>
 * 
 * <pre>{@code
 * // Capture thread
 * Thread captureThread = new Thread(() -> {
 *     try (NetPcap pcap = NetPcap.openLive("eth0")) {
 *         pcap.loop(-1, packet -> {
 *             if (filter(packet)) {
 *                 workQueue.put(packet.persist());
 *             }
 *         });
 *     }
 * });
 * 
 * // Worker threads
 * ExecutorService workers = Executors.newFixedThreadPool(4);
 * for (int i = 0; i < 4; i++) {
 *     workers.submit(() -> {
 *         Tcp tcp = new Tcp();  // Thread-local header
 *         while (running) {
 *             Packet p = workQueue.take();
 *             if (p.hasHeader(tcp)) {
 *                 process(tcp);
 *             }
 *             p.recycle();
 *         }
 *     });
 * }
 * }</pre>
 * 
 * <h2>Capture Methods</h2>
 * 
 * <table>
 * <caption>Capture Methods</caption>
 * <tr><th>Method</th><th>Blocking</th><th>Description</th></tr>
 * <tr><td>{@code loop(count, handler)}</td><td>Yes</td><td>Process until count or break</td></tr>
 * <tr><td>{@code dispatch(count, handler)}</td><td>Yes*</td><td>Process available up to count</td></tr>
 * <tr><td>{@code next()}</td><td>Yes*</td><td>Return next packet or null</td></tr>
 * <tr><td>{@code nextEx()}</td><td>Yes*</td><td>Return next with status code</td></tr>
 * </table>
 * <p>* Respects timeout from {@code setTimeout()}</p>
 * 
 * <h2>Platform Support</h2>
 * 
 * <table>
 * <caption>Platform Requirements</caption>
 * <tr><th>Platform</th><th>Native Library</th><th>Notes</th></tr>
 * <tr><td>Linux</td><td>libpcap 1.10+</td><td>Best performance</td></tr>
 * <tr><td>Windows</td><td>Npcap 1.0+</td><td>Admin rights may be needed</td></tr>
 * <tr><td>macOS</td><td>libpcap (system)</td><td>BPF device access required</td></tr>
 * </table>
 * 
 * <h2>Related Packages</h2>
 * 
 * <ul>
 * <li>{@code com.slytechs.sdk.jnetpcap} - Low-level Pcap bindings</li>
 * <li>{@code com.slytechs.sdk.protocol.core} - Packet, Header, PacketSettings</li>
 * <li>{@code com.slytechs.sdk.protocol.tcpip} - Ethernet, IPv4, IPv6, TCP, UDP</li>
 * <li>{@code com.slytechs.sdk.protocol.web} - HTTP, TLS, QUIC</li>
 * <li>{@code com.slytechs.sdk.protocol.infrastructure} - Routing, STP, discovery</li>
 * <li>{@code com.slytechs.sdk.common.memory.pool} - Pooling and persistence</li>
 * </ul>
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 3.0
 * @see NetPcap
 * @see PacketSettings
 * @see com.slytechs.sdk.jnetpcap.Pcap
 * @see com.slytechs.sdk.protocol.core.Packet
 */
package com.slytechs.sdk.jnetpcap.api;