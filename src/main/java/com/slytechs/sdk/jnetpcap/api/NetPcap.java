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
import com.slytechs.sdk.protocol.core.stack.ProtocolStack;
import com.slytechs.sdk.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;

/**
 * High-level packet capture interface with protocol dissection support.
 * 
 * <p>
 * NetPcap wraps the low-level {@link Pcap} bindings and integrates with the
 * {@link ProtocolStack} to provide automatic packet dissection. Packets
 * delivered through {@link #dispatch}, {@link #loop}, {@link #next}, and
 * {@link #nextEx} are fully dissected with protocol headers accessible via the
 * zero-allocation {@code hasHeader()} pattern.
 * </p>
 * 
 * <h2>Usage Examples</h2>
 * 
 * <h3>Simple Live Capture</h3>
 * 
 * <pre>{@code
 * try (NetPcap pcap = NetPcap.openLive("eth0", 65535, true, Duration.ofSeconds(1))) {
 * 	Ip4 ip = new Ip4();
 * 
 * 	pcap.loop(100, packet -> {
 * 		if (packet.hasHeader(ip)) {
 * 			System.out.printf("%s -> %s%n", ip.src(), ip.dst());
 * 		}
 * 	});
 * }
 * }</pre>
 * 
 * <h3>File Reading with Custom Stack</h3>
 * 
 * <pre>{@code
 * ProtocolStack stack = ProtocolStack.packetDissectionOnly();
 * stack.getPacketPolicy().zeroCopy();
 * 
 * try (NetPcap pcap = NetPcap.openOffline("capture.pcap", stack)) {
 * 	pcap.setFilter("tcp port 80");
 * 
 * 	Packet packet;
 * 	while ((packet = pcap.next()) != null) {
 * 		// Process packet...
 * 	}
 * }
 * }</pre>
 * 
 * <h3>Two-Stage Capture Configuration</h3>
 * 
 * <pre>{@code
 * try (NetPcap pcap = NetPcap.create("eth0")) {
 * 	pcap.setSnaplen(128)
 * 			.setPromisc(true)
 * 			.setTimeout(100)
 * 			.setImmediateMode(true)
 * 			.activate();
 * 
 * 	pcap.dispatch(1000, packet -> {
 * 		// Process packet...
 * 	});
 * }
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Pcap
 * @see ProtocolStack
 * @see PacketHandler
 */
public final class NetPcap extends BaseNetPcap implements Named, AutoCloseable {

	public static final String VERSION = Pcap.VERSION;

	public static void main(String[] args) throws PcapException {
		final String FILENAME = "pcaps/HTTP.cap";

		NetPcap.activateLicense();

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
	 * Constructs a list of network devices that can be opened with
	 * pcap_create(3PCAP) and pcap_activate(3PCAP) or with pcap_open_live(3PCAP).
	 * (Note that there may be network devices that cannot be opened by the process
	 * calling pcap_findalldevs(), because, for example, that process does not have
	 * sufficient privileges to open them for capturing; if so, those devices will
	 * not appear on the list.) If pcap_findalldevs() succeeds, the pointer pointed
	 * to by alldevsp is set to point to the first element of the list, or to NULL
	 * if no devices were found (this is considered success).
	 * 
	 * <p>
	 * Each element of the list is of type pcap_if_t, and has the following members:
	 * </p>
	 * <dl>
	 * <dt>next</dt>
	 * <dd>if not NULL, a pointer to the next element in the list; NULL for the last
	 * element of the list</dd>
	 * <dt>name</dt>
	 * <dd>a pointer to a string giving a name for the device to pass to
	 * pcap_open_live()</dd>
	 * <dt>description</dt>
	 * <dd>if not NULL, a pointer to a string giving a human-readable description of
	 * the device</dd>
	 * <dt>addresses</dt>
	 * <dd>a pointer to the first element of a list of network addresses for the
	 * device, or NULL if the device has no addresses</dd>
	 * </dl>
	 * <dl>
	 * <dt>flags</dt>
	 * <dd>device flags:
	 * <dt>PCAP_IF_LOOPBACK</dt>
	 * <dd>set if the device is a loopback interface</dd>
	 * <dt>PCAP_IF_UP</dt>
	 * <dd>set if the device is up</dd>
	 * <dt>PCAP_IF_RUNNING</dt>
	 * <dd>set if the device is running</dd>
	 * <dt>PCAP_IF_WIRELESS</dt>
	 * <dd>set if the device is a wireless interface; this includes IrDA as well as
	 * radio-based networks such as IEEE 802.15.4 and IEEE 802.11, so it doesn't
	 * just mean Wi-Fi</dd>
	 * </dl>
	 * <dl>
	 * <dt>PCAP_IF_CONNECTION_STATUS</dt>
	 * <dd>a bitmask for an indication of whether the adapter is connected or not;
	 * for wireless interfaces, "connected" means "associated with a network"
	 * <dt>PCAP_IF_CONNECTION_STATUS_UNKNOWN</dt>
	 * <dd>it's unknown whether the adapter is connected or not</dd>
	 * <dt>PCAP_IF_CONNECTION_STATUS_CONNECTED</dt>
	 * <dd>the adapter is connected</dd>
	 * <dt>PCAP_IF_CONNECTION_STATUS_DISCONNECTED</dt>
	 * <dd>the adapter is disconnected</dd>
	 * <dt>PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE</dt>
	 * <dd>the notion of "connected" and "disconnected" don't apply to this
	 * interface; for example, it doesn't apply to a loopback device</dd>
	 * </dl>
	 * 
	 * <p>
	 * Each element of the list of addresses is of type pcap_addr_t, and has the
	 * following members:
	 * </p>
	 * <dl>
	 * <dt>next</dt>
	 * <dd>if not NULL, a pointer to the next element in the list; NULL for the last
	 * element of the list</dd>
	 * <dt>addr</dt>
	 * <dd>a pointer to a struct sockaddr containing an address</dd>
	 * <dt>netmask</dt>
	 * <dd>if not NULL, a pointer to a struct sockaddr that contains the netmask
	 * corresponding to the address pointed to by addr</dd>
	 * <dt>broadaddr</dt>
	 * <dd>if not NULL, a pointer to a struct sockaddr that contains the broadcast
	 * address corresponding to the address pointed to by addr; may be null if the
	 * device doesn't support broadcasts</dd>
	 * <dt>dstaddr</dt>
	 * <dd>if not NULL, a pointer to a struct sockaddr that contains the destination
	 * address corresponding to the address pointed to by addr; may be null if the
	 * device isn't a point-to-point interface</dd>
	 * </dl>
	 * <p>
	 * Note that the addresses in the list of addresses might be IPv4 addresses,
	 * IPv6 addresses, or some other type of addresses, so you must check the
	 * sa_family member of the struct sockaddr before interpreting the contents of
	 * the address; do not assume that the addresses are all IPv4 addresses, or even
	 * all IPv4 or IPv6 addresses. IPv4 addresses have the value AF_INET, IPv6
	 * addresses have the value AF_INET6 (which older operating systems that don't
	 * support IPv6 might not define), and other addresses have other values.
	 * Whether other addresses are returned, and what types they might have is
	 * platform-dependent. For IPv4 addresses, the struct sockaddr pointer can be
	 * interpreted as if it pointed to a struct sockaddr_in; for IPv6 addresses, it
	 * can be interpreted as if it pointed to a struct sockaddr_in6.
	 * </p>
	 * <p>
	 * <b>For example</b>
	 * </p>
	 * 
	 * <pre>{@snippet : 
	 * 	List<PcapIf> list = Pcap.findAllDevs()
	 * }</pre>
	 *
	 * @return list of network devices
	 * @throws PcapException any pcap errors
	 * @since libpcap 0.7
	 */
	public static List<PcapIf> findAllDevs() throws PcapException {
		return Pcap.findAllDevs();
	}

	/**
	 * Create a list of network devices that can be opened with {@code Pcap#open}.
	 * <p>
	 * This routine can scan a directory for savefiles, list local capture devices,
	 * or list capture devices on a remote machine running an RPCAP server.
	 * </p>
	 * <p>
	 * For scanning for savefiles, it can be used on both UN*X systems and Windows
	 * systems; for each directory entry it sees, it tries to open the file as a
	 * savefile using pcap_open_offline(), and only includes it in the list of files
	 * if the open succeeds, so it filters out files for which the user doesn't have
	 * read permission, as well as files that aren't valid savefiles readable by
	 * libpcap.
	 * </p>
	 * <p>
	 * For listing local capture devices, it's just a wrapper around
	 * pcap_findalldevs(); full using pcap_findalldevs() will work on more platforms
	 * than full using pcap_findalldevs_ex().
	 * </p>
	 * <p>
	 * For listing remote capture devices, pcap_findalldevs_ex() is currently the
	 * only API available.
	 * </p>
	 * 
	 * <p>
	 * <em>Warning:</em>
	 * </p>
	 * 
	 * <blockquote>There may be network devices that cannot be opened with
	 * pcap_open() by the process calling pcap_findalldevs(), because, for example,
	 * that process might not have sufficient privileges to open them for capturing;
	 * if so, those devices will not appear on the list.</blockquote>
	 * 
	 * @param source   This source will be examined looking for adapters (local or
	 *                 remote) (e.g. source can be 'rpcap://' for local adapters or
	 *                 'rpcap://host:port' for adapters on a remote host) or pcap
	 *                 files (e.g. source can be 'file://c:/myfolder/').
	 * @param type     Type of the authentication required
	 * @param username The username that has to be used on the remote machine for
	 *                 authentication
	 * @param password The password that has to be used on the remote machine for
	 *                 authentication
	 * @return The list of the devices
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.9
	 * @since early days of WinPcap
	 */
	public static List<PcapIf> findAllDevsEx(String source, PcapSrc type, String username, String password)
			throws PcapException {
		return Pcap.findAllDevsEx(source, type, username, password);
	}

	/**
	 * Activates the product license using automatic key resolution.
	 * 
	 * <p>
	 * The license key is resolved from the following sources in order:
	 * </p>
	 * <ol>
	 * <li>Environment variable {@code JNETPCAP_LICENSE_KEY}</li>
	 * <li>Environment variable {@code JNETPCAP_LICENSE_DIR} → jnetpcap.lic</li>
	 * <li>System property {@code jnetpcap.license.key}</li>
	 * <li>System property {@code jnetpcap.license.dir} → jnetpcap.lic</li>
	 * <li>Environment variable {@code LICENSE_KEY}</li>
	 * <li>Environment variable {@code LICENSE_DIR} → jnetpcap.lic</li>
	 * <li>System property {@code license.key}</li>
	 * <li>System property {@code license.dir} → jnetpcap.lic</li>
	 * <li>Container secrets: {@code /run/secrets/jnetpcap.lic}</li>
	 * <li>User home: {@code ~/.jnetpcap/jnetpcap.lic}</li>
	 * <li>System path: {@code /etc/jnetpcap/jnetpcap.lic} (Linux) or
	 * {@code %PROGRAMFILES%\jnetpcap\jnetpcap.lic} (Windows)</li>
	 * <li>Universal home: {@code ~/.license/jnetpcap.lic}</li>
	 * <li>Universal system: {@code /etc/license/jnetpcap.lic}</li>
	 * <li>Classpath: {@code /license/jnetpcap.lic} (embedded community key)</li>
	 * </ol>
	 * 
	 * <p>
	 * The embedded community key provides unlimited activations with feature
	 * restrictions. To unlock all features, install a commercial key in any of the
	 * above locations.
	 * </p>
	 * 
	 * @throws LicenseException if no valid license key is found or activation fails
	 * @see #activateLicense(String)
	 */
	public static void activateLicense() throws LicenseException {
		Pcap.activateLicense();
	}

	/**
	 * Activates the product license using the specified key.
	 * 
	 * <p>
	 * Use this method when the license key is obtained programmatically or stored
	 * in a custom location not covered by automatic resolution.
	 * </p>
	 * 
	 * @param key the license key string (must be at least 20 characters)
	 * @throws LicenseException         if the key is invalid or activation fails
	 * @throws IllegalArgumentException if key is null or too short
	 * @see #activateLicense()
	 */
	public static void activateLicense(String key) throws LicenseException, IllegalArgumentException {
		Pcap.activateLicense(key);
	}

	/**
	 * Checks if the application version is compatible with this library version.
	 *
	 * @param applicationVersion the application's expected version
	 * @throws PcapVersionException if versions are incompatible
	 */
	public static void checkVersion(String applicationVersion) throws PcapVersionException {
		PcapVersionException.throwIfVersionMismatch(NetPcap.VERSION, applicationVersion);
	}

	/**
	 * Creates a capture handle for the specified device using two-stage
	 * configuration.
	 * 
	 * <p>
	 * The handle must be configured and activated before use. Uses default
	 * dissection-only protocol stack.
	 * </p>
	 *
	 * @param device the network interface
	 * @return a new NetPcap handle (not yet activated)
	 * @throws PcapException if handle creation fails
	 * @see #activate()
	 */
	public static NetPcap create(PcapIf device) throws PcapException {
		return create(device, new PacketSettings());
	}

	/**
	 * Creates a capture handle for the specified device with a custom protocol
	 * stack.
	 *
	 * @param device the network interface
	 * @param stack  the protocol stack for packet processing
	 * @return a new NetPcap handle (not yet activated)
	 * @throws PcapException if handle creation fails
	 */
	public static NetPcap create(PcapIf device, PacketSettings settings) throws PcapException {
		return create(device.name(), settings);
	}

	/**
	 * Creates a capture handle for the named device using two-stage configuration.
	 *
	 * @param device the device name (e.g., "eth0", "en0")
	 * @return a new NetPcap handle (not yet activated)
	 * @throws PcapException if handle creation fails
	 */
	public static NetPcap create(String device) throws PcapException {
		return create(device, new PacketSettings());
	}

	/**
	 * Creates a capture handle for the named device with a custom protocol stack.
	 *
	 * @param device the device name
	 * @param stack  the protocol stack for packet processing
	 * @return a new NetPcap handle (not yet activated)
	 * @throws PcapException if handle creation fails
	 */
	public static NetPcap create(String device, PacketSettings settings) throws PcapException {
		Pcap pcap = Pcap.create(device);
		return new NetPcap(pcap, settings, false);
	}

	/**
	 * Creates a "dead" handle for filter compilation or dump file writing.
	 *
	 * @param linktype the link-layer type
	 * @param snaplen  the snapshot length
	 * @return a new NetPcap handle
	 * @throws PcapException if handle creation fails
	 */
	public static NetPcap openDead(PcapDlt linktype, int snaplen) throws PcapException {
		return openDead(linktype, snaplen, new PacketSettings());
	}

	/**
	 * Creates a "dead" handle with a custom protocol stack.
	 *
	 * @param linktype the link-layer type
	 * @param snaplen  the snapshot length
	 * @param stack    the protocol stack
	 * @return a new NetPcap handle
	 * @throws PcapException if handle creation fails
	 */
	public static NetPcap openDead(PcapDlt linktype, int snaplen, PacketSettings settings) throws PcapException {
		Pcap pcap = Pcap.openDead(linktype, snaplen);
		return new NetPcap(pcap, settings, true);
	}

	/**
	 * Creates a "dead" handle with timestamp precision.
	 *
	 * @param linktype  the link-layer type
	 * @param snaplen   the snapshot length
	 * @param precision the timestamp precision
	 * @return a new NetPcap handle
	 * @throws PcapException if handle creation fails
	 */
	public static NetPcap openDeadWithTstampPrecision(PcapDlt linktype, int snaplen,
			PcapTStampPrecision precision) throws PcapException {
		return openDeadWithTstampPrecision(linktype, snaplen, precision, new PacketSettings());
	}

	/**
	 * Creates a "dead" handle with timestamp precision and custom stack.
	 *
	 * @param linktype  the link-layer type
	 * @param snaplen   the snapshot length
	 * @param precision the timestamp precision
	 * @param stack     the protocol stack
	 * @return a new NetPcap handle
	 * @throws PcapException if handle creation fails
	 */
	public static NetPcap openDeadWithTstampPrecision(PcapDlt linktype, int snaplen,
			PcapTStampPrecision precision, PacketSettings settings) throws PcapException {
		Pcap pcap = Pcap.openDeadWithTstampPrecision(linktype, snaplen, precision);
		return new NetPcap(pcap, settings, true);
	}

	/**
	 * Opens a device for live packet capture.
	 *
	 * @param device  the network interface
	 * @param snaplen maximum bytes to capture per packet
	 * @param promisc true for promiscuous mode
	 * @param timeout read timeout
	 * @param unit    timeout unit
	 * @return an activated NetPcap handle
	 * @throws PcapException if open fails
	 */
	public static NetPcap openLive(PcapIf device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit) throws PcapException {
		return openLive(device, snaplen, promisc, timeout, unit, new PacketSettings());
	}

	/**
	 * Opens a device for live packet capture with custom stack.
	 *
	 * @param device  the network interface
	 * @param snaplen maximum bytes to capture per packet
	 * @param promisc true for promiscuous mode
	 * @param timeout read timeout
	 * @param unit    timeout unit
	 * @param stack   the protocol stack
	 * @return an activated NetPcap handle
	 * @throws PcapException if open fails
	 */
	public static NetPcap openLive(PcapIf device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit, PacketSettings settings) throws PcapException {
		return openLive(device.name(), snaplen, promisc, timeout, unit, settings);
	}

	/**
	 * Opens a device for live packet capture using Duration.
	 *
	 * @param device  the device name
	 * @param snaplen maximum bytes to capture per packet
	 * @param promisc true for promiscuous mode
	 * @param timeout read timeout as Duration
	 * @return an activated NetPcap handle
	 * @throws PcapException if open fails
	 */
	public static NetPcap openLive(String device, int snaplen, boolean promisc,
			Duration timeout) throws PcapException {
		return openLive(device, snaplen, promisc, timeout, new PacketSettings());
	}

	/**
	 * Opens a device for live packet capture using Duration with custom stack.
	 *
	 * @param device  the device name
	 * @param snaplen maximum bytes to capture per packet
	 * @param promisc true for promiscuous mode
	 * @param timeout read timeout as Duration
	 * @param stack   the protocol stack
	 * @return an activated NetPcap handle
	 * @throws PcapException if open fails
	 */
	public static NetPcap openLive(String device, int snaplen, boolean promisc,
			Duration timeout, PacketSettings settings) throws PcapException {
		return openLive(device, snaplen, promisc, timeout.toMillis(), TimeUnit.MILLISECONDS, new PacketSettings());
	}

	/**
	 * Opens a device for live packet capture.
	 *
	 * @param device  the device name
	 * @param snaplen maximum bytes to capture per packet
	 * @param promisc true for promiscuous mode
	 * @param timeout read timeout value
	 * @param unit    timeout unit
	 * @return an activated NetPcap handle
	 * @throws PcapException if open fails
	 */
	public static NetPcap openLive(String device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit) throws PcapException {
		return openLive(device, snaplen, promisc, timeout, unit, new PacketSettings());
	}

	/**
	 * Opens a device for live packet capture with custom stack.
	 *
	 * @param device  the device name
	 * @param snaplen maximum bytes to capture per packet
	 * @param promisc true for promiscuous mode
	 * @param timeout read timeout value
	 * @param unit    timeout unit
	 * @param stack   the protocol stack
	 * @return an activated NetPcap handle
	 * @throws PcapException if open fails
	 */
	public static NetPcap openLive(String device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit, PacketSettings settings) throws PcapException {
		Pcap pcap = Pcap.openLive(device, snaplen, promisc, timeout, unit);
		return new NetPcap(pcap, settings, true);
	}

	/**
	 * Opens a capture file for reading.
	 *
	 * @param file the capture file
	 * @return an activated NetPcap handle
	 * @throws PcapException if file cannot be opened
	 */
	public static NetPcap openOffline(File file) throws PcapException {
		return openOffline(file, new PacketSettings());
	}

	/**
	 * Opens a capture file for reading with custom stack.
	 *
	 * @param file  the capture file
	 * @param stack the protocol stack
	 * @return an activated NetPcap handle
	 * @throws PcapException if file cannot be opened
	 */
	public static NetPcap openOffline(File file, PacketSettings settings) throws PcapException {
		return openOffline(file.getAbsolutePath(), settings);
	}

	/**
	 * Opens a capture file for reading.
	 *
	 * @param fname the filename
	 * @return an activated NetPcap handle
	 * @throws PcapException if file cannot be opened
	 */
	public static NetPcap openOffline(String fname) throws PcapException {
		return openOffline(fname, new PacketSettings());
	}

	/**
	 * Opens a capture file for reading with custom stack.
	 *
	 * @param fname the filename
	 * @param stack the protocol stack
	 * @return an activated NetPcap handle
	 * @throws PcapException if file cannot be opened
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
	 * 
	 */
	private void configurePipeline() {
		this.pipeline = new PacketPipeline(pcapApi, pcapApi.getPcapHeaderABI(), settings);
	}

	@Override
	public void activate() throws PcapException {
		super.activate();
		this.activated = true;
		configurePipeline();
	}

	/**
	 * Processes packets using the specified handler with user context.
	 * 
	 * <p>
	 * Packets are dissected through the protocol stack before being passed to the
	 * handler. The handler receives fully parsed packets with headers accessible
	 * via {@code hasHeader()}.
	 * </p>
	 *
	 * @param <U>     the user context type
	 * @param count   maximum packets to process (-1 for unlimited)
	 * @param handler the packet handler
	 * @param user    user context passed to handler
	 * @return number of packets processed, 0 on timeout, -1 on error, -2 on break
	 * @throws PcapException if capture fails
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
	 * Processes packets using a consumer-style handler.
	 *
	 * @param count   maximum packets to process (-1 for unlimited)
	 * @param handler the packet consumer
	 * @return number of packets processed, 0 on timeout, -1 on error, -2 on break
	 * @throws PcapException if capture fails
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
	 * Processes packets in a loop with user context.
	 * 
	 * <p>
	 * Unlike {@link #dispatch}, this method ignores read timeout and blocks until
	 * the specified count is reached or {@link #breakloop()} is called.
	 * </p>
	 *
	 * @param <U>     the user context type
	 * @param count   packets to process (-1 for infinite)
	 * @param handler the packet handler
	 * @param user    user context passed to handler
	 * @return number of packets processed, -1 on error, -2 on break
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
	 * Processes packets in a loop with consumer-style handler.
	 *
	 * @param count   packets to process (-1 for infinite)
	 * @param handler the packet consumer
	 * @return number of packets processed, -1 on error, -2 on break
	 */
	public int loop(int count, OfPacketConsumer handler) {
		dispatcher.userUpcall().setUserCallback((MemorySegment _, MemorySegment h, MemorySegment p) -> {
			Packet packet = pipeline.processPacket(h, p);

			if (packet != null)
				handler.accept(packet);
		});

		return dispatcher.loopRaw(count, MemorySegment.NULL);
	}

	@Override
	public String name() {
		return super.getName();
	}

	/**
	 * Retrieves the next packet without blocking.
	 * 
	 * <p>
	 * Returns null if no packet is available (timeout) or on EOF for offline
	 * captures. The returned packet is fully dissected with headers accessible via
	 * {@code hasHeader()}.
	 * </p>
	 * 
	 * <p>
	 * <b>Warning:</b> The returned Packet is only valid until the next call to
	 * {@code next()}, {@code nextEx()}, {@code dispatch()}, or {@code loop()}. Copy
	 * the packet data if you need to retain it.
	 * </p>
	 *
	 * @return the next dissected packet, or null on timeout/EOF
	 * @throws PcapException if capture fails
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
	 * Retrieves the next packet, distinguishing timeout from EOF.
	 * 
	 * <p>
	 * Unlike {@link #next()}, this method throws {@link TimeoutException} when no
	 * packet is available within the read timeout, allowing the caller to
	 * distinguish between timeout and end-of-file conditions.
	 * </p>
	 *
	 * @return the next dissected packet
	 * @throws PcapException    if capture fails or EOF reached
	 * @throws TimeoutException if read timeout expires with no packet
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
	 * Sends a packet on the network.
	 * 
	 * <p>
	 * The packet's raw data is transmitted. Any modifications made to the packet
	 * headers are reflected in the transmitted data. The entire packet from
	 * position 0 to capture length is sent.
	 * </p>
	 *
	 * @param packet the packet to send
	 * @throws PcapException if transmission fails
	 */
	public void sendPacket(Packet packet) throws PcapException {
		MemorySegment segment = packet.view().segment();
		long start = packet.view().start();
		int length = packet.captureLength();
		pcapApi.sendPacket(segment.asSlice(start, length), length);
	}

	/**
	 * Injects a packet on the network, returning bytes sent.
	 *
	 * @param packet the packet to inject
	 * @return number of bytes injected
	 * @throws PcapException if injection fails
	 */
	public int inject(Packet packet) throws PcapException {
		MemorySegment segment = packet.view().segment();
		long start = packet.view().start();
		int length = packet.captureLength();
		return pcapApi.inject(segment.asSlice(start, length), length);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setBufferSize(int bufferSize) throws PcapException {
		super.setBufferSize(bufferSize);
		return this;
	}

	/**
	 * Sets the kernel buffer size with unit specification.
	 *
	 * @param size the buffer size value
	 * @param unit the size unit
	 * @return this NetPcap for method chaining
	 * @throws PcapException if operation fails
	 */
	public NetPcap setBufferSize(long size, MemoryUnit unit) throws PcapException {
		return setBufferSize((int) unit.toBytes(size));
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setDatalink(int dlt) throws PcapException {
		super.setDatalink(dlt);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setDatalink(Optional<PcapDlt> dlt) throws PcapException {
		super.setDatalink(dlt);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setDatalink(PcapDlt dlt) throws PcapException {
		super.setDatalink(dlt);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setDirection(int dir) throws PcapException {
		super.setDirection(dir);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setDirection(Optional<PcapDirection> dir) throws PcapException {
		super.setDirection(dir);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setDirection(PcapDirection dir) throws PcapException {
		super.setDirection(dir);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setFilter(BpFilter bpfProgram) throws PcapException {
		super.setFilter(bpfProgram);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setFilter(Optional<BpFilter> bpfProgram) throws PcapException {
		super.setFilter(bpfProgram);
		return this;
	}

	/**
	 * Sets a BPF filter using a filter expression string.
	 *
	 * @param expression the filter expression (e.g., "tcp port 80")
	 * @return this NetPcap for method chaining
	 * @throws PcapException if filter compilation or application fails
	 */
	public NetPcap setFilter(String expression) throws PcapException {
		return setFilter(expression, true);
	}

	/**
	 * Sets a BPF filter with optimization control.
	 *
	 * @param expression the filter expression
	 * @param optimize   true to optimize the filter
	 * @return this NetPcap for method chaining
	 * @throws PcapException if filter compilation or application fails
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
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setImmediateMode(boolean enable) throws PcapException {
		super.setImmediateMode(enable);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setNonBlock(boolean nonBlock) throws PcapException {
		super.setNonBlock(nonBlock);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setPromisc(boolean promiscuousMode) throws PcapException {
		super.setPromisc(promiscuousMode);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setRfmon(boolean rfMonitor) throws PcapException {
		super.setRfmon(rfMonitor);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setSnaplen(int snaplen) throws PcapException {
		super.setSnaplen(snaplen);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setTimeout(int timeoutInMillis) throws PcapException {
		super.setTimeout(timeoutInMillis);
		return this;
	}

	/**
	 * Sets the read timeout using Duration.
	 *
	 * @param timeout the timeout duration
	 * @return this NetPcap for method chaining
	 * @throws PcapException if operation fails
	 */
	public NetPcap setTimeout(Duration timeout) throws PcapException {
		return setTimeout((int) timeout.toMillis());
	}

	/**
	 * Sets the read timeout with time unit.
	 *
	 * @param timeout the timeout value
	 * @param unit    the time unit
	 * @return this NetPcap for method chaining
	 * @throws PcapException if operation fails
	 */
	public NetPcap setTimeout(long timeout, TimeUnit unit) throws PcapException {
		return setTimeout((int) unit.toMillis(timeout));
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setTstampPrecision(PcapTStampPrecision precision) throws PcapException {
		super.setTstampPrecision(precision);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setTstampType(PcapTstampType type) throws PcapException {
		super.setTstampType(type);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setUncaughtExceptionHandler(Consumer<? super Throwable> exceptionHandler) {
		super.setUncaughtExceptionHandler(exceptionHandler);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		super.setUncaughtExceptionHandler(exceptionHandler);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return this NetPcap for method chaining
	 */
	@Override
	public NetPcap perror(String prefix) {
		super.perror(prefix);
		return this;
	}

	/**
	 * Returns whether this handle has been activated.
	 *
	 * @return true if activated
	 */
	public boolean isActivated() {
		return activated;
	}

	/**
	 * Returns a string representation including device name and state.
	 */
	@Override
	public String toString() {
		return String.format("NetPcap[%s, activated=%s]", getName(), activated);
	}
}