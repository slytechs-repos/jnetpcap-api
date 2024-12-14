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
package com.slytechs.jnet.jnetpcap;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.PcapHandler.OfArray;
import org.jnetpcap.PcapHandler.OfByteBuffer;
import org.jnetpcap.PcapHandler.OfMemorySegment;
import org.jnetpcap.PcapIf;
import org.jnetpcap.constant.PcapConstants;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.internal.DelegatePcap;

import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacket;
import com.slytechs.jnet.jnetruntime.NotFound;
import com.slytechs.jnet.jnetruntime.pipeline.DataProcessor;
import com.slytechs.jnet.jnetruntime.pipeline.DataProcessor.ProcessorFactory;
import com.slytechs.jnet.jnetruntime.pipeline.DataTransformer.OutputTransformer.EndPoint;
import com.slytechs.jnet.jnetruntime.pipeline.DataTypeTooCompilicated;
import com.slytechs.jnet.jnetruntime.pipeline.Pipeline;
import com.slytechs.jnet.jnetruntime.util.Flags;
import com.slytechs.jnet.jnetruntime.util.Named;
import com.slytechs.jnet.jnetruntime.util.config.BroadcastNetConfigurator;
import com.slytechs.jnet.jnetruntime.util.config.NetConfigurator;
import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.core.IpReassembly;

/**
 * Provides high-level packet capture and protocol settingsSupport using libpcap.
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
public class NetPcap extends DelegatePcap<NetPcap> implements Named {

	private static final MemorySegment DEFAULT_USER_ARG = MemorySegment.NULL;

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

	/**
	 * Creates a NetPcap instance using an existing Pcap handle. This method allows
	 * for integration with pre-existing Pcap configurations or external Pcap handle
	 * creation. Unlike other creation methods, this one may not require calling
	 * NetPcap::activate, depending on the state of the provided Pcap handle.
	 *
	 * @param pcapHandle The existing Pcap handle to use
	 * @param pcapType   The type of the Pcap handle (e.g., LIVE_CAPTURE,
	 *                   OFFLINE_READER, DEAD_HANDLE)
	 * @return A new NetPcap instance using the provided Pcap handle
	 * @throws IllegalArgumentException If the provided Pcap handle is null
	 * @throws IllegalStateException    If the Pcap handle is in an invalid state
	 *                                  for the specified PcapType
	 */
	public static NetPcap using(Pcap pcapHandle, PcapType pcapType) {
		return new NetPcap(pcapHandle, pcapType);
	}

	/**
	 * Creates a NetPcap instance for live packet capture using an Optional PcapIf
	 * device. This method requires NetPcap::activate to be called after creation to
	 * start the capture.
	 *
	 * @param deviceName An Optional containing the PcapIf device to use for capture
	 * @return A new NetPcap instance configured for live capture
	 * @throws PcapException If there's an error creating the Pcap instance
	 * @throws NotFound      If the Optional deviceName is empty
	 */
	public static NetPcap live(Optional<PcapIf> deviceName) throws PcapException, NotFound {
		if (deviceName.isEmpty())
			throw new NotFound("PcapIf device not found");

		return live(deviceName.get());
	}

	/**
	 * Creates a NetPcap instance for live packet capture using a PcapIf device.
	 * This method requires NetPcap::activate to be called after creation to start
	 * the capture.
	 *
	 * @param deviceName The PcapIf device to use for capture
	 * @return A new NetPcap instance configured for live capture
	 * @throws PcapException If there's an error creating the Pcap instance
	 */
	public static NetPcap live(PcapIf deviceName) throws PcapException {
		return new NetPcap(Pcap.create(deviceName), PcapType.LIVE_CAPTURE);
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
		return new NetPcap(Pcap.create(deviceName), PcapType.LIVE_CAPTURE);
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

		return new NetPcap(Pcap.openOffline(file), PcapType.OFFLINE_READER);
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

		return new NetPcap(Pcap.openOffline(filename), PcapType.OFFLINE_READER);
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
		return new NetPcap(Pcap.openDead(PcapDlt.EN10MB, MAX_SNAPLEN), PcapType.DEAD_HANDLE);
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
		return new NetPcap(Pcap.openDead(dlt, MAX_SNAPLEN), PcapType.DEAD_HANDLE);
	}

	private final NativePacketPipeline nativePipeline;
	private final RawPacketPipeline rawPipeline;
	private final PacketPipeline packetPipeline;

	private final List<Pipeline<?, ?>> pipelineList = new ArrayList<>();
	private final NetConfigurator configurator;

	private NetPcap(Pcap pcapHandle, PcapType pcapType) {
		super(pcapHandle);
		this.configurator = new BroadcastNetConfigurator(name());

		var abi = Objects.requireNonNull(getPcapHeaderABI(), "abi");
//		abi = PcapHeaderABI.COMPACT_BE;
		System.out.println("NetPcap2::init abi=" + abi);

		nativePipeline = new NativePacketPipeline(PcapUtils.shortName(name()));
		rawPipeline = new RawPacketPipeline(PcapUtils.shortName(name()));
		packetPipeline = new PacketPipeline(PcapUtils.shortName(name()), abi);

		pipelineList.add(nativePipeline);
		pipelineList.add(rawPipeline);

		nativePipeline.link(rawPipeline.entryPoint());
		nativePipeline.link(packetPipeline.entryPoint());

		packetPipeline.endPointOfPacket();
		System.out.println();
		System.out.println("NetPcap2::init packet=" + packetPipeline);

		System.out.println();
		System.out.println("NetPcap2::init raw=" + rawPipeline);

		System.out.println("NetPcap2::init native=" + nativePipeline);
	}

	public <T, T1, T_PROC extends DataProcessor<T, T_PROC>> T_PROC addProcessor(
			int priority,
			ProcessorFactory.Builder1Arg<T, T1, T_PROC> builder,
			T1 arg1) throws NotFound {

		var f = builder.newFactory(arg1);

		return addProcessor(priority, f);
	}

	/**
	 * Adds a processor to the pipeline with a specified priority.
	 *
	 * @param <T_PROC>         The type of the processor
	 * @param priority         The priority of the processor in the pipeline
	 * @param processorFactory The factory to create the processor
	 * @return The created processor
	 * @throws NotFound
	 */
	public <T, T_PROC extends DataProcessor<T, T_PROC>> T_PROC addProcessor(
			int priority,
			ProcessorFactory<T, T_PROC> processorFactory) throws NotFound {
		DataTypeTooCompilicated type = processorFactory.dataTypeTooCompilicated();
		Pipeline<T, ?> pipeline = getPipeline(type);

		var p = pipeline.addProcessor(priority, processorFactory);

		System.out.printf("NetPcap2::addProcessor(%s:%s) pipeline=%s%n", p.name(), type, pipeline);
		return p;
	}

	/**
	 * Adds a named processor to the pipeline with a specified priority.
	 *
	 * @param <T_PROC>         The type of the processor
	 * @param priority         The priority of the processor in the pipeline
	 * @param name             The name of the processor
	 * @param processorFactory The factory to create the named processor
	 * @return The created processor
	 */
	public <T, T_PROC extends DataProcessor<T, T_PROC>> T_PROC addProcessor(int priority, String name,
			ProcessorFactory.Named<T, T_PROC> processorFactory) {
		return null;
	}

	public <U> int dispatchArray(int count, OfArray<U> arrayHandler, U user) {

		var endPoint = rawPipeline
				.endPointOfArray()
				.userOpaque(user)
				.data(arrayHandler);

		int pktCount = dispatchNative0(count, DEFAULT_USER_ARG, endPoint);

		return pktCount;
	}

	public <U> int dispatchBuffer(int count, OfByteBuffer<U> byteBufferHandler, U user) {

		var endPoint = rawPipeline
				.endPointOfByteBuffer()
				.userOpaque(user)
				.data(byteBufferHandler);

		int pktCount = dispatchNative0(count, DEFAULT_USER_ARG, endPoint);

		return pktCount;
	}

	public int dispatchNative(int count, NativeCallback handler, MemorySegment user) {

		var endPoint = nativePipeline
				.endPointOfNative()
				.userOpaque(user)
				.data(handler);

		int pktCount = dispatchNative0(count, user, endPoint);

		return pktCount;
	}

	private int dispatchNative0(int count, MemorySegment user, EndPoint<?> endPoint) {
		try {
			int actualCount = super.dispatch(count, nativePipeline.entryPoint().data(), user);

			return actualCount;

		} finally {
			endPoint.resetAsEmpty();
		}
	}

	public <U> int dispatchPacket(int count, OfPacket<U> handler, U user) {

		var endPoint = packetPipeline
				.endPointOfPacket()
				.userOpaque(user)
				.data(handler);

		int pktCount = dispatchNative0(count, DEFAULT_USER_ARG, endPoint);

		return pktCount;
	}

	public <U> int dispatchSegment(int count, OfMemorySegment<U> memorySegmentHandler, U user) {

		var endPoint = nativePipeline
				.endPointOfSegment()
				.userOpaque(user)
				.data(memorySegmentHandler);

		int pktCount = dispatchNative0(count, DEFAULT_USER_ARG, endPoint);

		return pktCount;
	}

	@SuppressWarnings("unchecked")
	private <T> Pipeline<T, ?> getPipeline(DataTypeTooCompilicated dataTypeTooCompilicated) throws NotFound {
		return pipelineList.stream()
				.filter(p -> p.dataTypeTooCompilicated().equals(dataType))
				.map(p -> (Pipeline<T, ?>) p)
				.findAny()
				.orElseThrow(() -> new NotFound("pipeline for data type [%s.%s]"
						.formatted(dataType.getClass().getSimpleName(), dataType)));
	}

	public boolean nextEx(Packet packet) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.jnetruntime.util.Named#name()
	 */
	@Override
	public String name() {
		return getName();
	}

	public NetPcapConfig configure() {
		return new NetPcapConfig(configurator, this);
	}

	/**
	 * @param ipConfig
	 */
	public NetPcap setIpReassembler(IpReassembly reassembler) {
		throw new UnsupportedOperationException("not implemented yet");
	}
}
