/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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
package com.slytechs.jnet.jnetpcap.api;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.constant.PcapConstants;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.util.PcapVersionException;

import com.slytechs.jnet.jnetpcap.api.PacketHandler.OfNative;
import com.slytechs.jnet.jnetpcap.api.internal.PcapSource;
import com.slytechs.jnet.jnetpcap.api.internal.PcapUtils;
import com.slytechs.jnet.jnetpcap.api.internal.PostPcapPipeline;
import com.slytechs.jnet.jnetpcap.api.internal.PrePcapPipeline;
import com.slytechs.jnet.jnetpcap.api.processors.PacketRepeater;
import com.slytechs.jnet.jnetpcap.api.processors.PostProcessors;
import com.slytechs.jnet.jnetpcap.api.processors.PreProcessors;
import com.slytechs.jnet.jnetruntime.NotFound;
import com.slytechs.jnet.jnetruntime.frame.FrameABI;
import com.slytechs.jnet.jnetruntime.pipeline.OutputConnector;
import com.slytechs.jnet.jnetruntime.util.Flags;
import com.slytechs.jnet.jnetruntime.util.InvalidVersionException;
import com.slytechs.jnet.jnetruntime.util.MemoryUnit;
import com.slytechs.jnet.jnetruntime.util.Named;
import com.slytechs.jnet.jnetruntime.util.Registration;
import com.slytechs.jnet.jnetruntime.util.Version;
import com.slytechs.jnet.protocol.api.meta.PacketFormat;
import com.slytechs.jnet.protocol.tcpip.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.tcpip.network.IpReassembly;

/**
 * Provides high-level packet capture and protocol settingsSupport using
 * libpcap.
 * 
 * <h2>IP Fragment (IPF) Modes</h2> The NetPcap API supports IP fragment
 * reassembly and tracking. When enabled, the user's packet handler receives
 * fully reassembled IP datagrams instead of individual fragments, along with
 * other packets selected by the applied filter.
 * 
 * <p>
 * To enable IPF mode:
 * <ol>
 * <li>Use {@link #enableIpf(boolean)} before activating the pcap handle.</li>
 * <li>By default, both IPF tracking and reassembly are enabled.</li>
 * <li>IPF reassembly can be configured to:
 * <ul>
 * <li>Attach reassembled buffer to the last IP fragment</li>
 * <li>Insert as a new IP datagram into the dispatcher's packet stream</li>
 * </ul>
 * </li>
 * </ol>
 * </p>
 * 
 * <p>
 * Default behavior:
 * <ul>
 * <li>Individual IP fragments are not forwarded</li>
 * <li>Fully reassembled IP datagrams are delivered as new packets</li>
 * <li>Reassembled packets contain all combined IP fragment data</li>
 * </ul>
 * </p>
 * 
 * @author Mark Bednarczyk
 */
public final class NetPcap extends BaseNetPcap implements Named, AutoCloseable {

	/**
	 * Current version of the NetPcap implementation in MAJOR.MINOR.PATCH format.
	 */
	public static final String VERSION = "0.11.0";

	/**
	 * Artifact identifier for this library, used for dependency management and
	 * version checks.
	 */
	public static final String ARTIFACT_ID = "jnetpcap-api";

	/**
	 * Maven group identifier for this library, used in dependency declarations and
	 * artifact resolution.
	 */
	public static final String GROUP_ID = "com.slytechs.jnet.jnetpcap.api";

	/**
	 * Represents the maximum snapshot length for packet capture.
	 * 
	 * <p>
	 * This constant defines the maximum number of bytes that will be captured for
	 * each packet. It is set to the value of {@link PcapConstants#MAX_SNAPLEN},
	 * which typically corresponds to the maximum possible packet size for most
	 * network types.
	 * </p>
	 * 
	 * <p>
	 * Using this constant ensures consistency with the underlying libpcap library's
	 * maximum snapshot length. It's particularly useful when creating pcap handles
	 * or configuring capture parameters.
	 * </p>
	 * 
	 * <p>
	 * Note: While this value represents the maximum possible snapshot length, it's
	 * often advisable to use a smaller value in practice to optimize performance
	 * and reduce storage requirements, especially if you're only interested in
	 * specific parts of each packet.
	 * </p>
	 */
	public static final int MAX_SNAPLEN = PcapConstants.MAX_SNAPLEN;

	public static void main(String[] args) throws PcapException, NotFound, TimeoutException {
		try (var pcap = NetPcap.live()) {

			pcap.addErrorListener(Throwable::printStackTrace);

			pcap.activate();

			PreProcessors preProcessors = pcap.getPreProcessors();

			preProcessors.addProcessor(new PacketRepeater(2)
					.rewriteTimestamp(true)
					.setIfgForRepeated(10, TimeUnit.MILLISECONDS));

			preProcessors.addProcessor(21, new PacketRepeater(2));
//			preProcessors.addProcessor(new PacketDelay(20, TimeUnit.MILLISECONDS));
//
//			preProcessors.addProcessor(25, new PacketPlayer()
//					.setSpeed(2)
//					.setMinIfg(10, TimeUnit.MILLISECONDS));

			System.out.println(preProcessors.toStringInOut());

			PostProcessors postProcessors = pcap.getPostProcessors();
			System.out.println(postProcessors.toStringInOut());

			int count = 0;

			// count += pcap.dispatchPacket(1, new OfPacket<String>() {
			//
			// @Override
			// public void handlePacket(String user, Packet packet) {
			// System.out.println(packet);
			// }
			// }, "");

			count += pcap.dispatchNative(1, (PacketHandler.OfNative) (user, header, packet) -> {

//				System.out.println();
//				System.out.println("---- NATIVE CB ----");

//				System.out.print(HexStrings.toHexDump(header.asByteBuffer()));

				var hdr = new PcapHeader(header);

				System.out.println("Caught packet " + hdr);

			}, MemorySegment.NULL);

			// count += pcap.dispatchBuffer(1, (OfBuffer<String>) (user, header, packet) ->
			// {
			//
			// System.out.println();
			// System.out.println("---- BYTE BUFFER CB ----");
			//
			// System.out.println("Caught packet " + header);
			// System.out.println("User = " + user);
			//
			// }, "OfByteBuffer callback");

			// count += pcap.dispatchArray(1, (OfArray<String>) (user, header, packet) -> {
			//
			// System.out.println("---- ARRAY CB ----");
			//
			// System.out.println("Caught packet " + header);
			// System.out.println("User = " + user);
			//
			// }, "OfArray callback");

			// count += pcap.dispatchForeign(1, (OfForeign<String>) (user, header, packet)
			// -> {
			//
			// System.out.println();
			// System.out.println("---- MEMORY SEGMENT CB ----");
			//
			// System.out.println(HexStrings.toHexDump(header.asByteBuffer()));
			//
			// var hdr = new PcapHeader(header);
			//
			// System.out.println("Caught packet " + hdr);
			// System.out.println("User = " + user);
			//
			// }, "OfMemorySegment callback");

			// Packet packet = new Packet(PacketDescriptorType.PCAP);
			// pcap.nextPacket(packet);
			// count++;
			// System.out.println("---- NEXT_PACKET CB ----");
			// System.out.println("Caught packet " + packet);

			System.out.println();
			System.out.printf("processed %d packets%n", count);
		}

	}

	/**
	 * Performs semantic version compatibility checks between the installed library
	 * and application. Follows a minimal subset of Semantic Versioning rules
	 * focused on major and minor version compatibility.
	 * 
	 * <h3>Version Compatibility Rules</h3>
	 * <ul>
	 * <li>Major versions must match exactly (e.g. 2.x.x with 2.y.y)</li>
	 * <li>Application's minor version must not exceed library's minor version</li>
	 * <li>Patch versions are ignored in compatibility checks</li>
	 * </ul>
	 * 
	 * <h3>Examples</h3>
	 * 
	 * <pre>
	 * Compatible:
	 *   Library 2.3.0 with App 2.3.1   (matching major, matching minor)
	 *   Library 2.4.0 with App 2.3.0   (matching major, lib minor > app minor)
	 *   Library 2.0.0 with App 2.0.1   (matching major and minor)
	 * 
	 * Incompatible:
	 *   Library 3.0.0 with App 2.0.0   (major version mismatch)
	 *   Library 2.1.0 with App 2.2.0   (app minor exceeds lib minor)
	 * </pre>
	 *
	 * @param version Version string to check against this implementation (format:
	 *                MAJOR.MINOR.PATCH)
	 * @throws InvalidVersionException If versions are incompatible or malformed
	 * @see <a href="https://semver.org">Semantic Versioning 2.0.0</a>
	 */
	public static void checkVersion(String version) throws InvalidVersionException {
		Version.minimalCheck(ARTIFACT_ID, NetPcap.VERSION, version);

		try {
			Pcap.checkPcapVersion(Pcap.VERSION);
		} catch (PcapVersionException e) {
			throw new InvalidVersionException(e);
		}
	}

	/**
	 * Creates a NetPcap instance with a "dead" capture handle using default
	 * link-layer type and snapshot length. Unlike pcap_open_dead, this method
	 * requires NetPcap::activate to be called after creation to allow for
	 * additional configuration before finalizing the dead handle.
	 *
	 * @return A new NetPcap instance with a dead capture handle
	 * @throws PcapException If there's an error creating the Pcap instance
	 */
	public static NetPcap dead() throws PcapException {
		var pcap = Pcap.openDead(PcapDlt.EN10MB, PcapConstants.MAX_SNAPLEN);

		return new NetPcap(pcap);
	}

	/**
	 * Creates a NetPcap instance with a "dead" capture handle using specified
	 * link-layer type and default snapshot length. Unlike pcap_open_dead, this
	 * method requires NetPcap::activate to be called after creation to allow for
	 * additional configuration before finalizing the dead handle.
	 *
	 * @param dlt The data link type (PcapDlt) to use for the dead handle
	 * @return A new NetPcap instance with a dead capture handle
	 * @throws PcapException If there's an error creating the Pcap instance
	 */
	public static NetPcap dead(PcapDlt dlt) throws PcapException {
		var pcap = Pcap.openDead(dlt, PcapConstants.MAX_SNAPLEN);

		return new NetPcap(pcap);
	}

	/**
	 * Attempts to find the default network device for packet capture.
	 * 
	 * <p>
	 * This method searches for the default network device that can be used for
	 * packet capture. It returns an Optional that may contain a PcapIf object
	 * representing the default device.
	 * </p>
	 *
	 * @return An Optional containing the default PcapIf device if found, or an
	 *         empty Optional if no default device is available
	 * @throws PcapException If an error occurs while searching for the default
	 *                       device
	 */
	public static Optional<PcapIf> findDefaultDevice() throws PcapException {
		var list = listPcapDevices();
		var def = list.stream()
				.filter(dev -> Flags.isSet(dev.flags(), PcapIf.PCAP_IF_RUNNING))
				.findAny();

		return def;
	}

	/**
	 * Attempts to find a specific network device by its name.
	 * 
	 * <p>
	 * This method searches for a network device with the specified name and returns
	 * an Optional that may contain a PcapIf object representing the found device.
	 * </p>
	 *
	 * @param deviceName The name of the device to find
	 * @return An Optional containing the PcapIf device if found, or an empty
	 *         Optional if no device with the given name is found
	 * @throws PcapException If an error occurs while searching for the device
	 */
	public static Optional<PcapIf> findDevice(String deviceName) throws PcapException {
		return listPcapDevices().stream()
				.filter(dev -> deviceName.equalsIgnoreCase(dev.name()))
				.findAny();
	}

	/**
	 * Retrieves the default network device for packet capture.
	 * 
	 * <p>
	 * This method searches for and returns the default network device. Unlike
	 * findDefaultDevice(), this method throws an exception if no default device is
	 * found.
	 * </p>
	 *
	 * @return The PcapIf object representing the default device
	 * @throws NotFound      If no default device is found
	 * @throws PcapException If an error occurs while searching for the default
	 *                       device
	 */
	public static PcapIf getDefaultDevice() throws NotFound, PcapException {
		return findDefaultDevice()
				.orElseThrow(NotFound::new);
	}

	/**
	 * Retrieves a specific network device by its name.
	 * 
	 * <p>
	 * This method searches for a network device with the specified name. Unlike
	 * findDevice(), this method throws an exception if no device with the given
	 * name is found.
	 * </p>
	 *
	 * @param deviceName The name of the device to retrieve
	 * @return The PcapIf object representing the found device
	 * @throws NotFound      If no device with the given name is found
	 * @throws PcapException If an error occurs while searching for the device
	 */
	public static PcapIf getDevice(String deviceName) throws NotFound, PcapException {
		return findDevice(deviceName)
				.orElseThrow(() -> new NotFound(deviceName));
	}

	/**
	 * Lists all available network devices that can be used for packet capture.
	 * 
	 * <p>
	 * This method retrieves and returns a list of all network devices (interfaces)
	 * that are available for packet capture on the system.
	 * </p>
	 *
	 * @return A List of PcapIf objects representing all available network devices
	 * @throws PcapException If an error occurs while retrieving the list of devices
	 */
	public static List<PcapIf> listPcapDevices() throws PcapException {
		return Pcap.findAllDevs();
	}

	/**
	 * Creates a NetPcap instance for live packet capture using a device name
	 * string. This method requires NetPcap::activate to be called after creation to
	 * start the capture.
	 *
	 * @param deviceName The name of the device to use for capture
	 * @return A new NetPcap instance configured for live capture
	 * @throws PcapException If there's an error creating the Pcap instance
	 * @throws NotFound
	 */
	public static NetPcap live() throws PcapException, NotFound {
		var firstDevice = getDefaultDevice();
		var pcap = Pcap.create(firstDevice.name());

		return new NetPcap(pcap);
	}

	/**
	 * Creates a NetPcap instance for live packet capture using a device name
	 * string. This method requires NetPcap::activate to be called after creation to
	 * start the capture.
	 *
	 * @param deviceName The name of the device to use for capture
	 * @return A new NetPcap instance configured for live capture
	 * @throws PcapException If there's an error creating the Pcap instance
	 */
	public static NetPcap live(PcapIf device) throws PcapException {
		var pcap = Pcap.create(device.name());

		return new NetPcap(pcap);
	}

	/**
	 * Creates a NetPcap instance for live packet capture using a device name
	 * string. This method requires NetPcap::activate to be called after creation to
	 * start the capture.
	 *
	 * @param deviceName The name of the device to use for capture
	 * @return A new NetPcap instance configured for live capture
	 * @throws PcapException If there's an error creating the Pcap instance
	 */
	public static NetPcap live(String deviceName) throws PcapException {
		var pcap = Pcap.create(deviceName);

		return new NetPcap(pcap);
	}

	/**
	 * Creates a NetPcap instance for reading packets from a pcap file. Unlike
	 * pcap_open_offline, this method requires NetPcap::activate to be called after
	 * creation to allow for additional configuration before opening the file.
	 *
	 * @param file The File object representing the pcap file to read
	 * @return A new NetPcap instance configured for offline reading
	 * @throws PcapException         If there's an error creating the Pcap instance
	 * @throws FileNotFoundException If the specified file is not found
	 * @throws IOException           If there's an I/O error reading the file
	 */
	public static NetPcap offline(File file) throws PcapException, FileNotFoundException, IOException {
		PcapUtils.checkFileCanRead(file);

		var pcap = Pcap.openOffline(file.getAbsolutePath());

		return new NetPcap(pcap);
	}

	/**
	 * Creates a NetPcap instance for reading packets from a pcap file specified by
	 * filename. Unlike pcap_open_offline, this method requires NetPcap::activate to
	 * be called after creation to allow for additional configuration before opening
	 * the file.
	 *
	 * @param filename The name of the pcap file to read
	 * @return A new NetPcap instance configured for offline reading
	 * @throws PcapException         If there's an error creating the Pcap instance
	 * @throws FileNotFoundException If the specified file is not found
	 * @throws IOException           If there's an I/O error reading the file
	 */
	public static NetPcap offline(String filename) throws PcapException, FileNotFoundException, IOException {
		PcapUtils.checkFileCanRead(new File(filename));

		var pcap = Pcap.openOffline(filename);

		return new NetPcap(pcap);
	}

	/** Main native PCAP packet pipeline for packet dispatching */
	private final PrePcapPipeline prePipeline;

	private final PostPcapPipeline postPipeline;

	private final PacketDispatcher packetDispatcher;

	private final FrameABI frameABI;

	private NetPcap(Pcap pcap) {
		super(pcap);
		var pcapHeaderABI = pcap.getPcapHeaderABI();
		this.frameABI = FrameABI.valueOf(pcapHeaderABI.isCompact(), pcapHeaderABI.order());

		PcapSource pcapSource = super::dispatch; // Make sure to use Pcap.dispatch, not NetPcap.dispatchNative
		String shortName = PcapUtils.shortName(name());

		this.prePipeline = new PrePcapPipeline(shortName, this, frameABI, pcapSource);

		OutputConnector<OfNative> outputConnector = prePipeline::addOutput;
		PacketDispatcherSource source = prePipeline::capturePackets;

		this.postPipeline = new PostPcapPipeline(outputConnector, source, frameABI);
		this.packetDispatcher = new PipelinePacketDispatcher(prePipeline, postPipeline);
	}

	public Registration addErrorListener(Consumer<Throwable> listener) {
		return prePipeline.addPipelineErrorConsumer(listener);
	}

	@Override
	protected PacketDispatcher getPacketDispatcher() {
		return packetDispatcher;
	}

	public PostProcessors getPostProcessors() {
		return postPipeline;
	}

	public PreProcessors getPreProcessors() {
		return prePipeline;
	}

	/**
	 * @see com.slytechs.jnet.jnetruntime.util.Named#name()
	 */
	@Override
	public String name() {
		return getName();
	}

	/**
	 * @param i
	 * @param kilobytes
	 * @return
	 * @throws PcapException
	 */
	public NetPcap setBufferSize(int size, MemoryUnit unit) throws PcapException {
		super.setBufferSize(unit.toBytesAsInt(size));

		return this;
	}

	/**
	 * @param type2
	 * @return
	 */
	public NetPcap setDescriptorType(PacketDescriptorType type) {

		return this;
	}

	/**
	 * @param ipConfig
	 */
	public NetPcap setIpReassembler(IpReassembly reassembler) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @param packetFormat
	 * @return
	 */
	public NetPcap setPacketFormatter(PacketFormat packetFormat) {
		PacketDispatcher.DEFAULT_PACKET.setFormatter(packetFormat);

		return this;
	}
}
