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
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;
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
import com.slytechs.jnet.jnetruntime.pipeline.DataType;
import com.slytechs.jnet.jnetruntime.pipeline.Pipeline;
import com.slytechs.jnet.jnetruntime.util.Flags;
import com.slytechs.jnet.jnetruntime.util.HasName;

/**
 * @author Mark Bednarczyk
 *
 */
public class NetPcap2 extends DelegatePcap<NetPcap2> implements HasName {

	private static final MemorySegment DEFAULT_USER_ARG = MemorySegment.NULL;

	/**
	 * Open a specific network device
	 * 
	 * @throws PcapException
	 */
	public static NetPcap2 create(PcapIf networkDevice) throws PcapException {
		return new NetPcap2(Pcap.create(networkDevice));
	}

	public static Optional<PcapIf> findDefaultDevice() throws PcapException {
		var list = listPcapDevices();
		var def = list.stream()
				.filter(dev -> Flags.isSet(dev.flags(), PcapIf.PCAP_IF_RUNNING))
				.findAny();

		return def;
	}

	public static Optional<PcapIf> findDevice(String deviceName) throws PcapException {
		return listPcapDevices().stream()
				.filter(dev -> deviceName.equalsIgnoreCase(dev.name()))
				.findAny();
	}

	public static PcapIf getDefaultDevice() throws NotFound, PcapException {
		return findDefaultDevice()
				.orElseThrow(NotFound::new);
	}

	public static PcapIf getDevice(String deviceName) throws NotFound, PcapException {
		return findDevice(deviceName)
				.orElseThrow(() -> new NotFound(deviceName));
	}

	public static List<PcapIf> listPcapDevices() throws PcapException {
		return Pcap.findAllDevs();
	}

	public static NetPcap2 openDead(PcapDlt dlt) throws PcapException {
		return new NetPcap2(Pcap.openDead(dlt, PcapConstants.MAX_SNAPLEN));
	}

	public static NetPcap2 openDead(PcapDlt dlt, int maxSnaplen) throws PcapException {
		return new NetPcap2(Pcap.openDead(dlt, maxSnaplen));
	}

	public static NetPcap2 openOffline(File offlineFile) throws PcapException {
		return new NetPcap2(Pcap.openOffline(offlineFile));
	}

	private static final String shortName(String name) {
		if (name.contains("/")) {
			String[] c = name.split("\\/");
			name = c[c.length - 1];
		}

		return name;
	}

	private final NativePacketPipeline nativePipeline;

	private final RawPacketPipeline rawPipeline;

	private final List<Pipeline<?, ?>> pipelineList = new ArrayList<>();

	private NetPcap2(Pcap pcapHandle) {
		super(pcapHandle);

		nativePipeline = new NativePacketPipeline(shortName(name()));
		rawPipeline = new RawPacketPipeline(shortName(name()));

		pipelineList.add(nativePipeline);
		pipelineList.add(rawPipeline);

		nativePipeline.link(rawPipeline.entryPoint());

		System.out.println("NetPcap2::init native=" + nativePipeline);
		System.out.println();
		System.out.println("NetPcap2::init raw=" + rawPipeline);
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
		DataType type = processorFactory.dataType();
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

		rawPipeline
				.endPointOfArray()
				.data(arrayHandler);

		int pktCount = dispatchNative0(count, DEFAULT_USER_ARG);

		rawPipeline.endPointOfArray().empty();

		return pktCount;
	}

	public <U> int dispatchBuffer(int count, OfByteBuffer<U> byteBufferHandler, U user) {

		rawPipeline
				.endPointOfByteBuffer()
				.data(byteBufferHandler);

		int pktCount = dispatchNative0(count, DEFAULT_USER_ARG);

		rawPipeline.endPointOfByteBuffer().empty();

		return pktCount;
	}

	public int dispatchNative(int count, NativeCallback handler, MemorySegment user) {

		nativePipeline.endPoint().data(handler);

		int pktCount = dispatchNative0(count, user);

		nativePipeline.endPoint().clear();

		return pktCount;
	}

	private int dispatchNative0(int count, MemorySegment user) {
		return super.dispatch(count, nativePipeline.entryPoint().data(), user);
	}

	public <U> int dispatchPacket(int count, OfPacket<U> handler, U user) {
		throw new UnsupportedOperationException();
	}

	public <U> int dispatchSegment(int count, OfMemorySegment<U> memorySegmentHandler, U user) {
		throw new UnsupportedOperationException();
	}

	@SuppressWarnings("unchecked")
	private <T> Pipeline<T, ?> getPipeline(DataType dataType) throws NotFound {
		return pipelineList.stream()
				.filter(p -> p.dataType().equals(dataType))
				.map(p -> (Pipeline<T, ?>) p)
				.findAny()
				.orElseThrow(() -> new NotFound("pipeline for data type [%s.%s]"
						.formatted(dataType.getClass().getSimpleName(), dataType)));
	}

	/**
	 * @see com.slytechs.jnet.jnetruntime.util.HasName#name()
	 */
	@Override
	public String name() {
		return getName();
	}

}
