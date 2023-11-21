/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
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
package com.slytechs.jnetpcap.pro;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.Thread.UncaughtExceptionHandler;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.IntFunction;

import org.jnetpcap.BpFilter;
import org.jnetpcap.PcapActivatedException;
import org.jnetpcap.PcapException;
import org.jnetpcap.constant.PcapDirection;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapTStampPrecision;
import org.jnetpcap.constant.PcapTstampType;

import com.slytechs.jnetpcap.pro.PcapPro.Configuration;
import com.slytechs.jnetpcap.pro.internal.processor.PushProcesor;
import com.slytechs.jnetpcap.pro.internal.processor.PushProcesor.MemorySegmentProcessor;
import com.slytechs.jnetpcap.pro.internal.processor.PushProcesor.PacketProcessor;
import com.slytechs.jnetpcap.pro.internal.util.Installable;
import com.slytechs.jnetpcap.pro.processor.IpfReassembler;
import com.slytechs.jnetpcap.pro.processor.ProProcessor;
import com.slytechs.protocol.Frame.FrameNumber;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.meta.PacketFormat;
import com.slytechs.protocol.pack.core.constants.PacketDescriptorType;
import com.slytechs.protocol.runtime.time.TimestampUnit;
import com.slytechs.protocol.runtime.util.HasPriority;
import com.slytechs.protocol.runtime.util.MemoryUnit;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
class ProConfigurationImpl implements PcapPro.Configuration {

	private final PcapPro pcap;
	private final List<ProProcessor<?>> processorList = new ArrayList<>();

	private final List<MemorySegmentProcessor> memorySegmentProcessors = new ArrayList<>();
	private final List<PacketProcessor> packetProcessors = new ArrayList<>();

	/**
	 * 
	 */
	public ProConfigurationImpl(PcapPro pcap) {
		this.pcap = pcap;
	}

	private void initializeDataProcessing(ProProcessor<?> builder) {

		PushProcesor processing = builder.initialize();

		switch (processing) {

		case MemorySegmentProcessor p -> memorySegmentProcessors.add(p);
		case PacketProcessor p -> packetProcessors.add(p);

		default -> throw new IllegalStateException(""
				+ "Unsupported processor type %s".formatted(processing.getClass().getSimpleName()));
		}

	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#close()
	 */
	@Override
	public void close() throws PcapActivatedException, PcapException {

		Collections.sort(processorList, HasPriority.COMPARATOR);

		processorList.stream()
				.filter(ProProcessor::isEnabled)
				.forEach(this::initializeDataProcessing);

		pcap.activate();
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#install(int,
	 *      java.util.function.IntFunction)
	 */
	@Override
	public <T extends Installable> T install(int priority, IntFunction<T> processorFactory) {
		if (priority < 0)
			throw new IllegalArgumentException("negative priority values are not supported [%d]".formatted(priority));

		T installable = processorFactory.apply(priority);

		return switch (installable) {
		case ProProcessor<?> p -> installProcessor(p);

		default -> throw new IllegalStateException("Unsupported module, processor or feature [%s]"
				.formatted(processorFactory.getClass().getSimpleName()));
		};
	}

	@SuppressWarnings("unchecked")
	private <T extends Installable> T installProcessor(ProProcessor<?> processor) {

		this.processorList.add(processor);

		return (T) processor;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#install(java.util.function.IntFunction)
	 */
	@Override
	public <T extends Installable> T install(IntFunction<T> processorFactory) {
		return install(calcPriority(), processorFactory);
	}

	private int calcPriority() {

		int nextPriority = processorList.stream()
				.mapToInt(HasPriority::priority)
				.map(p -> p + 1)
				.max()
				.orElse(0);

		return nextPriority;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#read(java.io.File)
	 */
	@Override
	public void read(File configFile) throws FileNotFoundException, IOException {
		read(new FileReader(configFile));
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#read(java.io.Reader)
	 */
	@Override
	public void read(Reader in) throws IOException {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#read(java.lang.String)
	 */
	@Override
	public void read(String resource) throws IOException {
		read(new InputStreamReader(ProConfigurationImpl.class.getResourceAsStream(resource)));
	}

	@Override
	public Configuration setBufferSize(int bufferSize) throws PcapException {
		pcap.setBufferSize(bufferSize);
		return this;
	}

	@Override
	public Configuration setBufferSize(long size, MemoryUnit unit) throws PcapException {
		pcap.setBufferSize(size, unit);
		return this;
	}

	@Override
	public Configuration setDatalink(int dlt) throws PcapException {
		pcap.setDatalink(dlt);
		return this;
	}

	@Override
	public Configuration setDatalink(Optional<PcapDlt> dlt) throws PcapException {
		pcap.setDatalink(dlt);
		return this;
	}

	@Override
	public Configuration setDatalink(PcapDlt dlt) throws PcapException {
		pcap.setDatalink(dlt);
		return this;
	}

	@Override
	public Configuration setDirection(int dir) throws PcapException {
		pcap.setDirection(dir);
		return this;
	}

	@Override
	public Configuration setDirection(Optional<PcapDirection> dir) throws PcapException {
		pcap.setDirection(dir);
		return this;
	}

	@Override
	public Configuration setDirection(PcapDirection dir) throws PcapException {
		pcap.setDirection(dir);
		return this;
	}

	@Override
	public Configuration setFilter(BpFilter bpfProgram) throws PcapException {
		pcap.setFilter(bpfProgram);
		return this;
	}

	@Override
	public Configuration setFilter(Optional<BpFilter> bpfProgram) throws PcapException {
		pcap.setFilter(bpfProgram);
		return this;
	}

	@Override
	public Configuration setFrameNumber(FrameNumber frameNumberAssigner) {
		pcap.setFrameNumber(frameNumberAssigner);
		return this;
	}

	@Override
	public Configuration setFrameStartingNumber(long startingNo) {
		pcap.setFrameStartingNumber(startingNo);
		return this;
	}

	@Override
	public Configuration setImmediateMode(boolean enable) throws PcapException {
		pcap.setImmediateMode(enable);
		return this;
	}

	@Override
	public Configuration setNonBlock(boolean b) throws PcapException {
		pcap.setNonBlock(b);
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#setPacket(com.slytechs.protocol.Packet)
	 */
	@Override
	public Configuration setPacket(Packet reusablePacket) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	@Override
	public Configuration setPacketFactory(Function<PacketDescriptorType, Packet> factory) {
		pcap.setPacketFactory(factory);
		return this;
	}

	@Override
	public Configuration setPacketFormatter(PacketFormat formatter) {
		pcap.setPacketFormatter(formatter);
		return this;
	}

	@Override
	public Configuration setPacketType(PacketDescriptorType type) {
		pcap.setPacketType(type);
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#setPortNumber(int)
	 */
	@Override
	public Configuration setPortNumber(int portNo) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	@Override
	public Configuration setPromisc(boolean b) throws PcapException {
		pcap.setPromisc(b);
		return this;
	}

	public Configuration setPromisc(int enable) throws PcapException {
		pcap.setPromisc(enable);
		return this;
	}

	@Override
	public Configuration setRfmon(boolean enableRfmon) throws PcapException {
		pcap.setRfmon(enableRfmon);
		return this;
	}

	public Configuration setRfmon(int enableRfmon) throws PcapException {
		pcap.setRfmon(enableRfmon);
		return this;
	}

	@Override
	public Configuration setSnaplen(int snaplen) throws PcapException {
		pcap.setSnaplen(snaplen);
		return this;
	}

	@Override
	public Configuration setTimeout(int timeout) throws PcapException {
		pcap.setTimeout(timeout);
		return this;
	}

	@Override
	public Configuration setTimestampUnit(TimestampUnit unit) {
		pcap.setTimestampUnit(unit);
		return this;
	}

	@Override
	public Configuration setTstampPrecision(PcapTStampPrecision precision) throws PcapException {
		pcap.setTstampPrecision(precision);
		return this;
	}

	@Override
	public Configuration setTstampType(PcapTstampType type) throws PcapException {
		pcap.setTstampType(type);
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#setUncaughtExceptionHandler(java.util.function.Consumer)
	 */
	@Override
	public Configuration setUncaughtExceptionHandler(Consumer<? super Throwable> exceptionHandler) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#setUncaughtExceptionHandler(java.lang.Thread.UncaughtExceptionHandler)
	 */
	@Override
	public Configuration setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#uninstall(java.lang.Class)
	 */
	@Override
	public Configuration uninstall(Class<? extends ProcessorConfigurator<?>> processorClass) {
		processorList.removeIf(p -> p.getClass().isAssignableFrom(processorClass));

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#uninstall(com.slytechs.jnetpcap.pro.ProcessorConfigurator)
	 */
	@Override
	public Configuration uninstall(ProProcessor<?> processor) {
		processorList.remove(processor);

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#uninstAll(boolean,
	 *      boolean)
	 */
	@Override
	public Configuration uninstAll(boolean preProcessors, boolean postProcessors) {
		if (preProcessors)
			processorList.removeIf(p -> p.getClass().isAssignableFrom(MemorySegmentProcessor.class));

		if (postProcessors)
			processorList.removeIf(p -> p.getClass().isAssignableFrom(PacketProcessor.class));

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#uninstallAll()
	 */
	@Override
	public Configuration uninstallAll() {
		processorList.clear();

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PcapPro.Configuration#enableIpf(boolean)
	 */
	@Override
	public Configuration enableIpf(boolean b) {
		install(IpfReassembler::new)
				.enable(b);

		return this;
	}

}
