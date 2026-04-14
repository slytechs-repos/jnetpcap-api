/*
 * Copyright 2005-2025 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.jnetpcap.api;

import java.io.File;
import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.foreign.MemorySegment;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import com.slytechs.jnet.jnetpcap.api.foreign.MemorySegmentPair;
import com.slytechs.jnet.jnetpcap.api.foreign.NetPcapDispatcher;
import com.slytechs.sdk.common.license.LicenseException;
import com.slytechs.sdk.common.memory.MemoryUnit;
import com.slytechs.sdk.common.util.Named;
import com.slytechs.sdk.jnetpcap.BpFilter;
import com.slytechs.sdk.jnetpcap.Pcap;
import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.jnetpcap.PcapIf;
import com.slytechs.sdk.jnetpcap.api.PacketHandler.OfPacket;
import com.slytechs.sdk.jnetpcap.api.PacketHandler.OfPacketConsumer;
import com.slytechs.sdk.jnetpcap.constant.PcapDirection;
import com.slytechs.sdk.jnetpcap.constant.PcapDlt;
import com.slytechs.sdk.jnetpcap.constant.PcapSrc;
import com.slytechs.sdk.jnetpcap.constant.PcapTStampPrecision;
import com.slytechs.sdk.jnetpcap.constant.PcapTstampType;
import com.slytechs.sdk.jnetpcap.util.PcapVersionException;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.PacketSettings;
import com.slytechs.sdk.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;

/**
 * High-level packet capture and protocol dissection API.
 *
 * <p>
 * {@code NetPcap} wraps the low-level {@link Pcap} bindings and integrates
 * protocol dissection so that packets delivered through {@link #dispatch},
 * {@link #loop}, {@link #next}, and {@link #nextEx} are fully dissected before
 * reaching the caller. Protocol headers are accessible via the
 * zero-allocation {@code hasHeader()} pattern.
 * </p>
 *
 * <p>
 * License activation is implicit — the Community Edition activates
 * automatically on the first {@code NetPcap} operation. No setup is required.
 * Commercial keys are resolved from environment variables, system properties,
 * file paths, and container secrets. See {@link #activateLicense()} for the
 * full resolution order if manual activation is needed.
 * </p>
 *
 * <h2>Factory Methods</h2>
 *
 * <table>
 * <caption>NetPcap factory methods</caption>
 * <tr><th>Method</th><th>Use Case</th><th>Activated</th></tr>
 * <tr><td>{@link #create(String)}</td>
 *     <td>Two-stage live capture — configure then activate</td><td>No</td></tr>
 * <tr><td>{@link #openLive(String, int, boolean, Duration)}</td>
 *     <td>One-shot live capture</td><td>Yes</td></tr>
 * <tr><td>{@link #openOffline(String)}</td>
 *     <td>Read pcap/pcapng file</td><td>Yes</td></tr>
 * <tr><td>{@link #openDead(PcapDlt, int)}</td>
 *     <td>Filter compilation or dump file writing</td><td>Yes</td></tr>
 * </table>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>Live Capture with BPF Filter</h3>
 * <pre>{@code
 * try (NetPcap pcap = NetPcap.create("eth0")) {
 *     pcap.setSnaplen(65535)
 *         .setPromisc(true)
 *         .setTimeout(Duration.ofMillis(100))
 *         .activate();
 *
 *     pcap.setFilter("tcp port 443");
 *
 *     Ip4 ip4 = new Ip4();
 *     Tcp tcp = new Tcp();
 *
 *     pcap.loop(-1, packet -> {
 *         if (packet.hasHeader(ip4) && packet.hasHeader(tcp))
 *             System.out.printf("%s:%d -> %s:%d%n",
 *                 ip4.src(), tcp.srcPort(),
 *                 ip4.dst(), tcp.dstPort());
 *     });
 * }
 * }</pre>
 *
 * <h3>Offline File Reading with Protocol Dissection</h3>
 * <pre>{@code
 * PacketSettings settings = new PacketSettings().dissect();
 *
 * try (NetPcap pcap = NetPcap.openOffline("capture.pcap", settings)) {
 *     Ethernet eth = new Ethernet();
 *     Ip4 ip4 = new Ip4();
 *
 *     pcap.loop(-1, packet -> {
 *         if (packet.hasHeader(eth) && packet.hasHeader(ip4))
 *             System.out.printf("%s -> %s%n", ip4.src(), ip4.dst());
 *     });
 * }
 * }</pre>
 *
 * <h3>Multi-threaded Producer-Consumer</h3>
 * <pre>{@code
 * BlockingQueue<Packet> queue = new LinkedBlockingQueue<>(10000);
 *
 * // Capture thread
 * try (NetPcap pcap = NetPcap.openLive("eth0", 65535, true, Duration.ofSeconds(1))) {
 *     pcap.loop(-1, packet -> {
 *         if (filter(packet))
 *             queue.put(packet.persist());   // persist before callback returns
 *     });
 * }
 *
 * // Worker thread — each needs its own header instances
 * Tcp tcp = new Tcp();
 * while (running) {
 *     Packet p = queue.poll(100, TimeUnit.MILLISECONDS);
 *     if (p != null) {
 *         if (p.hasHeader(tcp)) process(tcp);
 *         p.recycle();
 *     }
 * }
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Pcap
 * @see PacketSettings
 * @see PacketHandler
 */
public final class NetPcap extends BaseNetPcap implements Named, AutoCloseable {

	/** The jNetPcap library version string. */
	public static final String VERSION = Pcap.VERSION;

	/**
	 * Explicitly activates the SDK license using automatic key resolution.
	 *
	 * <p>
	 * In most cases this method does not need to be called — the license activates
	 * automatically on the first {@code NetPcap} operation. Call this method only
	 * if you need to activate before any capture operations, or to force a specific
	 * key resolution.
	 * </p>
	 *
	 * <p>The key is resolved from the following sources in order:</p>
	 * <ol>
	 * <li>Environment variable {@code JNETPCAP_LICENSE_KEY}</li>
	 * <li>Environment variable {@code JNETPCAP_LICENSE_DIR} → {@code jnetpcap.lic}</li>
	 * <li>System property {@code jnetpcap.license.key}</li>
	 * <li>System property {@code jnetpcap.license.dir} → {@code jnetpcap.lic}</li>
	 * <li>Environment variable {@code LICENSE_KEY}</li>
	 * <li>Environment variable {@code LICENSE_DIR} → {@code jnetpcap.lic}</li>
	 * <li>System property {@code license.key}</li>
	 * <li>System property {@code license.dir} → {@code jnetpcap.lic}</li>
	 * <li>Container secrets: {@code /run/secrets/jnetpcap.lic}</li>
	 * <li>User home: {@code ~/.jnetpcap/jnetpcap.lic}</li>
	 * <li>System path: {@code /etc/jnetpcap/jnetpcap.lic} (Linux) or
	 *     {@code %PROGRAMFILES%\jnetpcap\jnetpcap.lic} (Windows)</li>
	 * <li>Universal home: {@code ~/.license/jnetpcap.lic}</li>
	 * <li>Universal system: {@code /etc/license/jnetpcap.lic}</li>
	 * <li>Classpath: {@code /license/jnetpcap.lic} (embedded Community Edition key)</li>
	 * </ol>
	 *
	 * <p>
	 * If no commercial key is found the embedded Community Edition key is used,
	 * providing unlimited captures with telemetry enabled.
	 * </p>
	 *
	 * @throws LicenseException if no valid key is found or activation fails
	 * @see #activateLicense(String)
	 */
	public static void activateLicense() throws LicenseException {
		Pcap.activateLicense();
	}

	/**
	 * Explicitly activates the SDK license using the specified key.
	 *
	 * <p>
	 * Use this method when the license key is obtained programmatically or stored
	 * in a location not covered by the automatic resolution order in
	 * {@link #activateLicense()}.
	 * </p>
	 *
	 * @param key the license key string
	 * @throws LicenseException         if the key is invalid or activation fails
	 * @throws IllegalArgumentException if key is null or malformed
	 * @see #activateLicense()
	 */
	public static void activateLicense(String key) throws LicenseException, IllegalArgumentException {
		Pcap.activateLicense(key);
	}

	/**
	 * Checks that the application version is compatible with this library version.
	 *
	 * @param applicationVersion the version string the application was built against
	 * @throws PcapVersionException if the versions are incompatible
	 */
	public static void checkVersion(String applicationVersion) throws PcapVersionException {
		PcapVersionException.throwIfVersionMismatch(NetPcap.VERSION, applicationVersion);
	}

	/**
	 * Creates a capture handle for the specified device using two-stage
	 * configuration.
	 *
	 * <p>
	 * The handle is not yet active. Call configuration setters then
	 * {@link #activate()} before dispatching packets. Uses default
	 * {@link PacketSettings}.
	 * </p>
	 *
	 * <pre>{@code
	 * try (NetPcap pcap = NetPcap.create(device)) {
	 *     pcap.setSnaplen(65535)
	 *         .setPromisc(true)
	 *         .setTimeout(Duration.ofMillis(100))
	 *         .activate();
	 *
	 *     pcap.setFilter("tcp");
	 *     pcap.loop(-1, handler);
	 * }
	 * }</pre>
	 *
	 * @param device the network interface to capture on
	 * @return a new, unactivated {@code NetPcap} handle
	 * @throws PcapException if handle creation fails
	 * @see #activate()
	 * @see #create(PcapIf, PacketSettings)
	 */
	public static NetPcap create(PcapIf device) throws PcapException {
		return create(device, new PacketSettings());
	}

	/**
	 * Creates a capture handle for the specified device with custom packet settings.
	 *
	 * @param device   the network interface to capture on
	 * @param settings packet structure and dissection configuration
	 * @return a new, unactivated {@code NetPcap} handle
	 * @throws PcapException if handle creation fails
	 * @see #activate()
	 */
	public static NetPcap create(PcapIf device, PacketSettings settings) throws PcapException {
		return create(device.name(), settings);
	}

	/**
	 * Creates a capture handle for the named device using two-stage configuration.
	 *
	 * <p>Uses default {@link PacketSettings}.</p>
	 *
	 * @param device the device name (e.g., {@code "eth0"}, {@code "en0"})
	 * @return a new, unactivated {@code NetPcap} handle
	 * @throws PcapException if handle creation fails
	 * @see #activate()
	 * @see #create(String, PacketSettings)
	 */
	public static NetPcap create(String device) throws PcapException {
		return create(device, new PacketSettings());
	}

	/**
	 * Creates a capture handle for the named device with custom packet settings.
	 *
	 * @param device   the device name (e.g., {@code "eth0"}, {@code "en0"})
	 * @param settings packet structure and dissection configuration
	 * @return a new, unactivated {@code NetPcap} handle
	 * @throws PcapException if handle creation fails
	 * @see #activate()
	 */
	public static NetPcap create(String device, PacketSettings settings) throws PcapException {
		Pcap pcap = Pcap.create(device);
		return new NetPcap(pcap, settings, false);
	}

	/**
	 * Returns all network interfaces available for capture on this system.
	 *
	 * <p>
	 * Interfaces that the calling process cannot open (e.g., insufficient
	 * privileges) are silently omitted from the returned list. An empty list is a
	 * valid result and does not indicate an error.
	 * </p>
	 *
	 * <p>Each {@link PcapIf} provides:</p>
	 * <ul>
	 * <li>{@code name()} — interface name to pass to {@link #create} or
	 *     {@link #openLive}</li>
	 * <li>{@code description()} — human-readable description (optional)</li>
	 * <li>{@code addresses()} — list of network addresses (IPv4, IPv6, or other)</li>
	 * <li>{@code isLoopback()}, {@code isUp()}, {@code isRunning()},
	 *     {@code isWireless()} — interface flags</li>
	 * </ul>
	 *
	 * <pre>{@code
	 * NetPcap.findAllDevs().stream()
	 *     .filter(d -> d.isUp() && !d.isLoopback())
	 *     .forEach(d -> System.out.println(d.name()));
	 * }</pre>
	 *
	 * @return list of available network interfaces, possibly empty
	 * @throws PcapException if the underlying pcap call fails
	 * @since libpcap 0.7
	 */
	public static List<PcapIf> findAllDevs() throws PcapException {
		return Pcap.findAllDevs();
	}

	/**
	 * Returns network interfaces from a remote RPCAP source or directory of
	 * savefiles.
	 *
	 * <p>
	 * Extends {@link #findAllDevs()} with support for remote capture via the RPCAP
	 * protocol and for scanning a directory of pcap savefiles.
	 * </p>
	 *
	 * <p>Source format examples:</p>
	 * <ul>
	 * <li>{@code "rpcap://"} — local interfaces (equivalent to
	 *     {@link #findAllDevs()})</li>
	 * <li>{@code "rpcap://host:2002"} — interfaces on a remote RPCAP host</li>
	 * <li>{@code "file:///path/to/dir"} — pcap savefiles in a directory</li>
	 * </ul>
	 *
	 * @param source   the source URI to scan for interfaces or savefiles
	 * @param type     authentication type for remote sources
	 * @param username username for remote authentication (or null)
	 * @param password password for remote authentication (or null)
	 * @return list of available interfaces or savefiles
	 * @throws PcapException if the source cannot be reached or enumeration fails
	 * @since libpcap 1.9 / WinPcap
	 */
	public static List<PcapIf> findAllDevsEx(String source, PcapSrc type, String username, String password)
			throws PcapException {
		return Pcap.findAllDevsEx(source, type, username, password);
	}

	public static void main(String[] args) throws PcapException {
		final String FILENAME = "pcaps/HTTP.cap";

		PacketSettings settings = new PacketSettings()
				.dissect();

		Ethernet ethernet = new Ethernet();
		Ip4 ip4 = new Ip4();
		try (NetPcap pcap = NetPcap.openOffline(FILENAME, settings)) {

			pcap.dispatch(1, packet -> {

				System.out.println(packet.descriptor());

				System.out.println(packet);

				if (packet.hasHeader(ip4)) {
					System.out.println("IPv4: " + ip4.src() + " → " + ip4.dst());
					System.out.println("Version: " + ip4.version());
					System.out.println("Protocol: " + ip4.protocol());
				}

				if (packet.hasHeader(ethernet))
					System.out.println(ethernet);
			});
		}
	}

	/**
	 * Creates a "dead" handle for filter compilation or dump file writing.
	 *
	 * <p>
	 * A dead handle is not bound to any live interface and cannot capture packets.
	 * It is used to compile BPF filters (via {@link #compile}) or to write pcap
	 * dump files (via {@link #dumpOpen}) without an active capture.
	 * </p>
	 *
	 * <p>Uses default {@link PacketSettings}.</p>
	 *
	 * @param linktype the link-layer type for the dead handle
	 * @param snaplen  the snapshot length
	 * @return an activated dead {@code NetPcap} handle
	 * @throws PcapException if handle creation fails
	 * @see #openDeadWithTstampPrecision(PcapDlt, int, PcapTStampPrecision)
	 */
	public static NetPcap openDead(PcapDlt linktype, int snaplen) throws PcapException {
		return openDead(linktype, snaplen, new PacketSettings());
	}

	/**
	 * Creates a "dead" handle with custom packet settings.
	 *
	 * @param linktype the link-layer type for the dead handle
	 * @param snaplen  the snapshot length
	 * @param settings packet structure and dissection configuration
	 * @return an activated dead {@code NetPcap} handle
	 * @throws PcapException if handle creation fails
	 */
	public static NetPcap openDead(PcapDlt linktype, int snaplen, PacketSettings settings) throws PcapException {
		Pcap pcap = Pcap.openDead(linktype, snaplen);
		return new NetPcap(pcap, settings, true);
	}

	/**
	 * Creates a "dead" handle with specific timestamp precision.
	 *
	 * <p>Uses default {@link PacketSettings}.</p>
	 *
	 * @param linktype  the link-layer type
	 * @param snaplen   the snapshot length
	 * @param precision the timestamp precision
	 * @return an activated dead {@code NetPcap} handle
	 * @throws PcapException if handle creation fails
	 */
	public static NetPcap openDeadWithTstampPrecision(PcapDlt linktype, int snaplen,
			PcapTStampPrecision precision) throws PcapException {
		return openDeadWithTstampPrecision(linktype, snaplen, precision, new PacketSettings());
	}

	/**
	 * Creates a "dead" handle with specific timestamp precision and custom packet
	 * settings.
	 *
	 * @param linktype  the link-layer type
	 * @param snaplen   the snapshot length
	 * @param precision the timestamp precision
	 * @param settings  packet structure and dissection configuration
	 * @return an activated dead {@code NetPcap} handle
	 * @throws PcapException if handle creation fails
	 */
	public static NetPcap openDeadWithTstampPrecision(PcapDlt linktype, int snaplen,
			PcapTStampPrecision precision, PacketSettings settings) throws PcapException {
		Pcap pcap = Pcap.openDeadWithTstampPrecision(linktype, snaplen, precision);
		return new NetPcap(pcap, settings, true);
	}

	/**
	 * Opens a network interface for live packet capture.
	 *
	 * <p>
	 * The returned handle is already activated. Uses default {@link PacketSettings}.
	 * </p>
	 *
	 * @param device  the network interface to capture on
	 * @param snaplen maximum bytes to capture per packet (use 65535 for full
	 *                packets)
	 * @param promisc {@code true} to enable promiscuous mode
	 * @param timeout read timeout
	 * @param unit    timeout unit
	 * @return an activated {@code NetPcap} handle
	 * @throws PcapException if the interface cannot be opened
	 * @see #create(PcapIf) for two-stage configuration with more options
	 */
	public static NetPcap openLive(PcapIf device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit) throws PcapException {
		return openLive(device, snaplen, promisc, timeout, unit, new PacketSettings());
	}

	/**
	 * Opens a network interface for live packet capture with custom packet settings.
	 *
	 * @param device   the network interface to capture on
	 * @param snaplen  maximum bytes to capture per packet
	 * @param promisc  {@code true} to enable promiscuous mode
	 * @param timeout  read timeout
	 * @param unit     timeout unit
	 * @param settings packet structure and dissection configuration
	 * @return an activated {@code NetPcap} handle
	 * @throws PcapException if the interface cannot be opened
	 */
	public static NetPcap openLive(PcapIf device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit, PacketSettings settings) throws PcapException {
		return openLive(device.name(), snaplen, promisc, timeout, unit, settings);
	}

	/**
	 * Opens a network interface for live packet capture.
	 *
	 * <p>Uses default {@link PacketSettings}.</p>
	 *
	 * @param device  the device name (e.g., {@code "eth0"}, {@code "en0"})
	 * @param snaplen maximum bytes to capture per packet
	 * @param promisc {@code true} to enable promiscuous mode
	 * @param timeout read timeout as {@link Duration}
	 * @return an activated {@code NetPcap} handle
	 * @throws PcapException if the interface cannot be opened
	 */
	public static NetPcap openLive(String device, int snaplen, boolean promisc,
			Duration timeout) throws PcapException {
		return openLive(device, snaplen, promisc, timeout, new PacketSettings());
	}

	/**
	 * Opens a network interface for live packet capture with custom packet settings.
	 *
	 * @param device   the device name
	 * @param snaplen  maximum bytes to capture per packet
	 * @param promisc  {@code true} to enable promiscuous mode
	 * @param timeout  read timeout as {@link Duration}
	 * @param settings packet structure and dissection configuration
	 * @return an activated {@code NetPcap} handle
	 * @throws PcapException if the interface cannot be opened
	 */
	public static NetPcap openLive(String device, int snaplen, boolean promisc,
			Duration timeout, PacketSettings settings) throws PcapException {
		return openLive(device, snaplen, promisc, timeout.toMillis(), TimeUnit.MILLISECONDS, new PacketSettings());
	}

	/**
	 * Opens a network interface for live packet capture.
	 *
	 * <p>Uses default {@link PacketSettings}.</p>
	 *
	 * @param device  the device name
	 * @param snaplen maximum bytes to capture per packet
	 * @param promisc {@code true} to enable promiscuous mode
	 * @param timeout read timeout value
	 * @param unit    timeout unit
	 * @return an activated {@code NetPcap} handle
	 * @throws PcapException if the interface cannot be opened
	 */
	public static NetPcap openLive(String device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit) throws PcapException {
		return openLive(device, snaplen, promisc, timeout, unit, new PacketSettings());
	}

	/**
	 * Opens a network interface for live packet capture with custom packet settings.
	 *
	 * @param device   the device name
	 * @param snaplen  maximum bytes to capture per packet
	 * @param promisc  {@code true} to enable promiscuous mode
	 * @param timeout  read timeout value
	 * @param unit     timeout unit
	 * @param settings packet structure and dissection configuration
	 * @return an activated {@code NetPcap} handle
	 * @throws PcapException if the interface cannot be opened
	 */
	public static NetPcap openLive(String device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit, PacketSettings settings) throws PcapException {
		Pcap pcap = Pcap.openLive(device, snaplen, promisc, timeout, unit);
		return new NetPcap(pcap, settings, true);
	}

	/**
	 * Opens a pcap or pcapng capture file for reading.
	 *
	 * <p>Uses default {@link PacketSettings}.</p>
	 *
	 * @param file the capture file
	 * @return an activated {@code NetPcap} handle
	 * @throws PcapException if the file cannot be opened or is not a valid capture
	 *                       file
	 * @see #openOffline(File, PacketSettings)
	 */
	public static NetPcap openOffline(File file) throws PcapException {
		return openOffline(file, new PacketSettings());
	}

	/**
	 * Opens a capture file for reading with custom packet settings.
	 *
	 * @param file     the capture file
	 * @param settings packet structure and dissection configuration
	 * @return an activated {@code NetPcap} handle
	 * @throws PcapException if the file cannot be opened
	 */
	public static NetPcap openOffline(File file, PacketSettings settings) throws PcapException {
		return openOffline(file.getAbsolutePath(), settings);
	}

	/**
	 * Opens a pcap or pcapng capture file for reading.
	 *
	 * <p>Uses default {@link PacketSettings}.</p>
	 *
	 * <pre>{@code
	 * try (NetPcap pcap = NetPcap.openOffline("capture.pcap")) {
	 *     pcap.loop(-1, packet -> System.out.println(packet));
	 * }
	 * }</pre>
	 *
	 * @param fname the path to the capture file
	 * @return an activated {@code NetPcap} handle
	 * @throws PcapException if the file cannot be opened or is not a valid capture
	 *                       file
	 * @see #openOffline(String, PacketSettings)
	 */
	public static NetPcap openOffline(String fname) throws PcapException {
		return openOffline(fname, new PacketSettings());
	}

	/**
	 * Opens a capture file for reading with custom packet settings.
	 *
	 * <pre>{@code
	 * PacketSettings settings = new PacketSettings().dissect();
	 *
	 * try (NetPcap pcap = NetPcap.openOffline("capture.pcap", settings)) {
	 *     Ip4 ip4 = new Ip4();
	 *     pcap.loop(-1, packet -> {
	 *         if (packet.hasHeader(ip4))
	 *             System.out.println(ip4.src() + " -> " + ip4.dst());
	 *     });
	 * }
	 * }</pre>
	 *
	 * @param fname    the path to the capture file
	 * @param settings packet structure and dissection configuration
	 * @return an activated {@code NetPcap} handle
	 * @throws PcapException if the file cannot be opened
	 */
	public static NetPcap openOffline(String fname, PacketSettings settings) throws PcapException {
		Pcap pcap = Pcap.openOffline(fname);
		return new NetPcap(pcap, settings, true);
	}

	private final PacketSettings settings;
	private PacketPipeline pipeline;
	private boolean activated;
	private final NetPcapDispatcher dispatcher;
	private final MemorySegmentPair userPair = new MemorySegmentPair();
	private final MemorySegment pcapHandle;

	private NetPcap(Pcap pcap, PacketSettings settings, boolean activated) {
		super(pcap);
		this.settings = Objects.requireNonNull(settings, "stack");
		this.pcapHandle = pcap.handle();

		this.activated = activated;
		this.dispatcher = new NetPcapDispatcher(
				pcap.handle(),
				pcap.getPcapHeaderABI(),
				pcap::breakloop);

		if (activated) {
			configurePipeline();
		}
	}

	/**
	 * Activates this capture handle.
	 *
	 * <p>
	 * Must be called after {@link #create} and before any packet dispatch methods.
	 * Configuration setters ({@code setSnaplen}, {@code setPromisc}, etc.) must be
	 * called before activation. {@link #setFilter} must be called after activation.
	 * </p>
	 *
	 * @throws PcapException if activation fails (e.g., insufficient privileges,
	 *                       device not found)
	 */
	@Override
	public void activate() throws PcapException {
		super.activate();
		this.activated = true;
		configurePipeline();
	}

	/**
	 * 
	 */
	private void configurePipeline() {
		this.pipeline = new PacketPipeline(pcapApi, pcapApi.getPcapHeaderABI(), settings);
	}

	/**
	 * Processes up to {@code count} packets, passing each to the handler with a
	 * user context object.
	 *
	 * <p>
	 * Packets are dissected through the protocol pipeline before the handler is
	 * called. The handler receives a fully dissected {@link Packet} with protocol
	 * headers accessible via {@code hasHeader()}.
	 * </p>
	 *
	 * <p>
	 * Returns after processing {@code count} packets, after a read timeout, or
	 * after {@link #breakloop()} is called. Unlike {@link #loop}, this method
	 * respects the read timeout configured via {@link #setTimeout}.
	 * </p>
	 *
	 * <p>
	 * The {@link Packet} passed to the handler is only valid for the duration of
	 * the callback. Call {@link Packet#persist()} to retain it beyond the callback.
	 * </p>
	 *
	 * @param <U>     the user context type
	 * @param count   maximum packets to process; use {@code -1} for unlimited
	 * @param handler the packet handler
	 * @param user    user context passed to each handler invocation
	 * @return number of packets processed, {@code 0} on timeout,
	 *         {@code -1} on error, {@code -2} if {@link #breakloop()} was called
	 * @throws PcapException if capture fails
	 * @see #loop(int, OfPacketConsumer)
	 */
	public <U> int dispatch(int count, OfPacket<U> handler, U user) throws PcapException {

		dispatcher.userUpcall().setUserCallback((MemorySegment _, MemorySegment h, MemorySegment p) -> {
			Packet packet = pipeline.processPacket(h, p);

			if (packet != null)
				handler.handlePacket(user, packet);
		});

		return dispatcher.dispatchRaw(count, MemorySegment.NULL);
	}

	/**
	 * Processes up to {@code count} packets, passing each to a consumer-style
	 * handler.
	 *
	 * <p>
	 * Equivalent to {@link #dispatch(int, OfPacket, Object)} without a user context
	 * object. The handler is a standard {@link java.util.function.Consumer Consumer}
	 * of {@link Packet}.
	 * </p>
	 *
	 * <p>
	 * The {@link Packet} passed to the handler is only valid for the duration of
	 * the callback. Call {@link Packet#persist()} to retain it beyond the callback.
	 * </p>
	 *
	 * @param count   maximum packets to process; use {@code -1} for unlimited
	 * @param handler the packet consumer
	 * @return number of packets processed, {@code 0} on timeout,
	 *         {@code -1} on error, {@code -2} if {@link #breakloop()} was called
	 * @throws PcapException if capture fails
	 * @see #loop(int, OfPacketConsumer)
	 */
	public int dispatch(int count, OfPacketConsumer handler) throws PcapException {

		dispatcher.userUpcall().setUserCallback((MemorySegment _, MemorySegment h, MemorySegment p) -> {
			Packet packet = pipeline.processPacket(h, p);

			if (packet != null)
				handler.accept(packet);
		});

		return pcapApi.dispatch(count, (Void _, MemorySegment h, MemorySegment p) -> {
			Packet packet = pipeline.processPacket(h, p);

			if (packet != null)
				handler.accept(packet);

		}, null);
	}

	/**
	 * Injects a packet on the network, returning the number of bytes sent.
	 *
	 * <p>
	 * Functionally equivalent to {@link #sendPacket(Packet)} but returns the byte
	 * count rather than void. Prefer this method when the sent byte count needs to
	 * be verified.
	 * </p>
	 *
	 * @param packet the packet to inject
	 * @return the number of bytes injected
	 * @throws PcapException if injection fails
	 * @see #sendPacket(Packet)
	 */
	public int inject(Packet packet) throws PcapException {
		MemorySegment segment = packet.view().segment();
		long start = packet.view().start();
		int length = packet.captureLength();
		return pcapApi.inject(segment.asSlice(start, length), length);
	}

	/**
	 * Returns whether this handle has been activated.
	 *
	 * @return {@code true} if {@link #activate()} has been called or the handle was
	 *         created via {@link #openLive}, {@link #openOffline}, or
	 *         {@link #openDead}
	 */
	public boolean isActivated() {
		return activated;
	}

	/**
	 * Processes packets in a loop with a user context object.
	 *
	 * <p>
	 * Unlike {@link #dispatch}, this method ignores the read timeout and blocks
	 * until exactly {@code count} packets are processed or {@link #breakloop()} is
	 * called. Use {@code count = -1} for infinite capture.
	 * </p>
	 *
	 * <p>
	 * The {@link Packet} passed to the handler is only valid for the duration of
	 * the callback. Call {@link Packet#persist()} to retain it beyond the callback.
	 * </p>
	 *
	 * @param <U>     the user context type
	 * @param count   packets to process; use {@code -1} for infinite
	 * @param handler the packet handler
	 * @param user    user context passed to each handler invocation
	 * @return number of packets processed, {@code -1} on error,
	 *         {@code -2} if {@link #breakloop()} was called
	 * @see #dispatch(int, OfPacketConsumer)
	 */
	public <U> int loop(int count, OfPacket<U> handler, U user) {
		dispatcher.userUpcall().setUserCallback((MemorySegment _, MemorySegment h, MemorySegment p) -> {
			Packet packet = pipeline.processPacket(h, p);

			if (packet != null)
				handler.handlePacket(user, packet);
		});

		return dispatcher.loopRaw(count, MemorySegment.NULL);
	}

	/**
	 * Processes packets in a loop with a consumer-style handler.
	 *
	 * <p>
	 * Unlike {@link #dispatch}, this method ignores the read timeout and blocks
	 * until exactly {@code count} packets are processed or {@link #breakloop()} is
	 * called. Use {@code count = -1} for infinite capture.
	 * </p>
	 *
	 * <p>
	 * The {@link Packet} passed to the handler is only valid for the duration of
	 * the callback. Call {@link Packet#persist()} to retain it beyond the callback.
	 * </p>
	 *
	 * @param count   packets to process; use {@code -1} for infinite
	 * @param handler the packet consumer
	 * @return number of packets processed, {@code -1} on error,
	 *         {@code -2} if {@link #breakloop()} was called
	 * @see #dispatch(int, OfPacketConsumer)
	 */
	public int loop(int count, OfPacketConsumer handler) {
		dispatcher.userUpcall().setUserCallback((MemorySegment _, MemorySegment h, MemorySegment p) -> {
			Packet packet = pipeline.processPacket(h, p);

			if (packet != null)
				handler.accept(packet);
		});

		return dispatcher.loopRaw(count, MemorySegment.NULL);
	}

	/** {@inheritDoc} */
	@Override
	public String name() {
		return super.getName();
	}

	/**
	 * Returns the next available packet without blocking indefinitely.
	 *
	 * <p>
	 * Returns {@code null} if no packet is available within the read timeout, or at
	 * end-of-file for offline captures. The returned packet is fully dissected with
	 * headers accessible via {@code hasHeader()}.
	 * </p>
	 *
	 * <p>
	 * <strong>Lifetime warning:</strong> The returned {@link Packet} is only valid
	 * until the next call to {@code next()}, {@code nextEx()}, {@code dispatch()},
	 * or {@code loop()}. Call {@link Packet#persist()} if you need to retain it.
	 * </p>
	 *
	 * @return the next dissected packet, or {@code null} on timeout or EOF
	 * @throws PcapException if capture fails
	 * @see #nextEx()
	 */
	@Override
	public Packet next() throws PcapException {
		dispatcher.next(userPair);
		if (userPair.pkt == null)
			return null;

		Packet packet = pipeline.processPacket(userPair.hdr, userPair.pkt);

		return packet;
	}

	/**
	 * Returns the next available packet, distinguishing timeout from EOF.
	 *
	 * <p>
	 * Unlike {@link #next()}, this method throws {@link TimeoutException} on read
	 * timeout, allowing the caller to distinguish between timeout (no packet yet)
	 * and end-of-file (no more packets).
	 * </p>
	 *
	 * <p>
	 * <strong>Lifetime warning:</strong> The returned {@link Packet} is only valid
	 * until the next call to any dispatch method. Call {@link Packet#persist()} if
	 * you need to retain it.
	 * </p>
	 *
	 * @return the next dissected packet
	 * @throws PcapException    if capture fails or EOF is reached on an offline
	 *                          capture
	 * @throws TimeoutException if the read timeout expires with no packet available
	 * @see #next()
	 */
	@Override
	public Packet nextEx() throws PcapException, TimeoutException {
		dispatcher.nextEx(userPair);
		if (userPair.pkt == null)
			return null;

		Packet packet = pipeline.processPacket(userPair.hdr, userPair.pkt);

		return packet;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap perror(String prefix) {
		super.perror(prefix);
		return this;
	}

	/**
	 * Transmits a packet on the network.
	 *
	 * <p>
	 * The packet's raw bytes from position {@code 0} to {@code captureLength()} are
	 * transmitted. Any header modifications made before calling this method are
	 * reflected in the transmitted data.
	 * </p>
	 *
	 * @param packet the packet to transmit
	 * @throws PcapException if transmission fails (e.g., insufficient privileges,
	 *                       network error)
	 * @see #inject(Packet)
	 */
	public void sendPacket(Packet packet) throws PcapException {
		MemorySegment segment = packet.view().segment();
		long start = packet.view().start();
		int length = packet.captureLength();
		pcapApi.sendPacket(segment.asSlice(start, length), length);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setBufferSize(int bufferSize) throws PcapException {
		super.setBufferSize(bufferSize);
		return this;
	}

	/**
	 * Sets the kernel capture buffer size.
	 *
	 * <p>Must be called before {@link #activate()}.</p>
	 *
	 * @param size the buffer size value
	 * @param unit the size unit (e.g., {@link MemoryUnit#MEGABYTES})
	 * @return this {@code NetPcap} for method chaining
	 * @throws PcapException if the operation fails
	 */
	public NetPcap setBufferSize(long size, MemoryUnit unit) throws PcapException {
		return setBufferSize((int) unit.toBytes(size));
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setDatalink(int dlt) throws PcapException {
		super.setDatalink(dlt);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setDatalink(Optional<PcapDlt> dlt) throws PcapException {
		super.setDatalink(dlt);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setDatalink(PcapDlt dlt) throws PcapException {
		super.setDatalink(dlt);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setDirection(int dir) throws PcapException {
		super.setDirection(dir);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setDirection(Optional<PcapDirection> dir) throws PcapException {
		super.setDirection(dir);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setDirection(PcapDirection dir) throws PcapException {
		super.setDirection(dir);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setFilter(BpFilter bpfProgram) throws PcapException {
		super.setFilter(bpfProgram);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setFilter(Optional<BpFilter> bpfProgram) throws PcapException {
		super.setFilter(bpfProgram);
		return this;
	}

	/**
	 * Compiles and applies a BPF filter expression.
	 *
	 * <p>
	 * Must be called after {@link #activate()}. The filter is compiled with
	 * optimization enabled. For optimization control use
	 * {@link #setFilter(String, boolean)}.
	 * </p>
	 *
	 * <pre>{@code
	 * pcap.setFilter("tcp port 80 or tcp port 443");
	 * pcap.setFilter("host 192.168.1.1 and not port 22");
	 * pcap.setFilter("tcp[tcpflags] & tcp-syn != 0");  // SYN packets only
	 * }</pre>
	 *
	 * @param expression the BPF filter expression
	 * @return this {@code NetPcap} for method chaining
	 * @throws PcapException if the expression is invalid or cannot be applied
	 * @see #setFilter(String, boolean)
	 */
	public NetPcap setFilter(String expression) throws PcapException {
		return setFilter(expression, true);
	}

	/**
	 * Compiles and applies a BPF filter expression with optimization control.
	 *
	 * @param expression the BPF filter expression
	 * @param optimize   {@code true} to optimize the compiled filter
	 * @return this {@code NetPcap} for method chaining
	 * @throws PcapException if the expression is invalid or cannot be applied
	 */
	public NetPcap setFilter(String expression, boolean optimize) throws PcapException {
		try (BpFilter filter = compile(expression, optimize)) {
			super.setFilter(filter);
		}
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p>Must be called before {@link #activate()}.</p>
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setImmediateMode(boolean enable) throws PcapException {
		super.setImmediateMode(enable);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setNonBlock(boolean nonBlock) throws PcapException {
		super.setNonBlock(nonBlock);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p>Must be called before {@link #activate()}.</p>
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setPromisc(boolean promiscuousMode) throws PcapException {
		super.setPromisc(promiscuousMode);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p>Must be called before {@link #activate()}. Only supported on
	 * wireless interfaces.</p>
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setRfmon(boolean rfMonitor) throws PcapException {
		super.setRfmon(rfMonitor);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p>Must be called before {@link #activate()}.</p>
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setSnaplen(int snaplen) throws PcapException {
		super.setSnaplen(snaplen);
		return this;
	}

	/**
	 * Sets the read timeout using a {@link Duration}.
	 *
	 * <p>Must be called before {@link #activate()}.</p>
	 *
	 * @param timeout the read timeout
	 * @return this {@code NetPcap} for method chaining
	 * @throws PcapException if the operation fails
	 */
	public NetPcap setTimeout(Duration timeout) throws PcapException {
		return setTimeout((int) timeout.toMillis());
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p>Must be called before {@link #activate()}.</p>
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setTimeout(int timeoutInMillis) throws PcapException {
		super.setTimeout(timeoutInMillis);
		return this;
	}

	/**
	 * Sets the read timeout with an explicit time unit.
	 *
	 * <p>Must be called before {@link #activate()}.</p>
	 *
	 * @param timeout the timeout value
	 * @param unit    the time unit
	 * @return this {@code NetPcap} for method chaining
	 * @throws PcapException if the operation fails
	 */
	public NetPcap setTimeout(long timeout, TimeUnit unit) throws PcapException {
		return setTimeout((int) unit.toMillis(timeout));
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p>Must be called before {@link #activate()}.</p>
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setTstampPrecision(PcapTStampPrecision precision) throws PcapException {
		super.setTstampPrecision(precision);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p>Must be called before {@link #activate()}.</p>
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setTstampType(PcapTstampType type) throws PcapException {
		super.setTstampType(type);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setUncaughtExceptionHandler(Consumer<? super Throwable> exceptionHandler) {
		super.setUncaughtExceptionHandler(exceptionHandler);
		return this;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return this {@code NetPcap} for method chaining
	 */
	@Override
	public NetPcap setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		super.setUncaughtExceptionHandler(exceptionHandler);
		return this;
	}

	/**
	 * Returns a string representation of this handle including the device name and
	 * activation state.
	 *
	 * @return e.g., {@code "NetPcap[eth0, activated=true]"}
	 */
	@Override
	public String toString() {
		return String.format("NetPcap[%s, activated=%s]", getName(), activated);
	}
}