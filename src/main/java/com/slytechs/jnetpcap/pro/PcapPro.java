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
import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.foreign.MemoryAddress;
import java.util.Optional;
import java.util.Stack;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import org.jnetpcap.Pcap0_4;
import org.jnetpcap.Pcap0_6;
import org.jnetpcap.Pcap1_0;
import org.jnetpcap.Pcap1_5;
import org.jnetpcap.Pcap1_9;
import org.jnetpcap.PcapActivatedException;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapIf;
import org.jnetpcap.constant.PcapCode;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapTStampPrecision;
import org.jnetpcap.internal.NonSealedPcap;
import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.internal.StandardPcapDispatcher;
import org.jnetpcap.util.PcapPacketRef;

import com.slytechs.jnetpcap.pro.PcapConfigurator.PostFactory;
import com.slytechs.jnetpcap.pro.PcapConfigurator.PostProcessor;
import com.slytechs.jnetpcap.pro.PcapConfigurator.PreFactory;
import com.slytechs.jnetpcap.pro.PcapConfigurator.PreProcessor;
import com.slytechs.jnetpcap.pro.PcapProHandler.OfPacketConsumer;
import com.slytechs.jnetpcap.pro.internal.CaptureStatisticsImpl;
import com.slytechs.jnetpcap.pro.internal.MainPacketDispatcher;
import com.slytechs.jnetpcap.pro.internal.PacketDispatcher;
import com.slytechs.jnetpcap.pro.internal.PacketDispatcherConfig;
import com.slytechs.protocol.Frame.FrameNumber;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.descriptor.PacketDissector;
import com.slytechs.protocol.meta.PacketFormat;
import com.slytechs.protocol.pack.core.constants.PacketDescriptorType;
import com.slytechs.protocol.runtime.time.TimestampUnit;

/**
 * Pcap packet capture with high level packet and protocol support.
 * 
 * <h2>IPF Modes</h2> The pro pcap API provides support for IP fragment
 * reassembly and tracking. When enabled, the user packet handler will receive
 * fully reassembled IP datagrams instead of individual fragments along with any
 * other type of packets selected by the packet filter applied.
 * <p>
 * To enable IPF mode, use the fluent method {@link #enable(boolean)} before the
 * pcap handle is activated. Once enabled, numerous defaults are used and can be
 * changed by the use of the pcap handle. By default, IPF tracking and
 * reassembly are both enabled. Of course these settings can be changed by use
 * of {@link #enableTracking(boolean)} and {@link #enableReassembly(boolean)}
 * respectively. Further more, IPF reassembly can be configured to attach IPF
 * reassembled buffer to the last IP fragment and/or inserted as a new IP
 * data-gram into the dispatcher's packet stream. This way the user packet
 * handler will receive fully reassembled IP datagrams as packets. The default
 * is to not forward individual IP fragments, but deliver the fully reassembled
 * IP data-gram as a new packet, containing all of the IP fragment data
 * combined.
 * </p>
 * <p>
 * If you would like to receive all of the IP fragments used in the reassembly
 * as well, use the method {@link #enablePassthrough(boolean)} which will cause
 * all of the IP fragments to be passed through in their original form.
 * </p>
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public final class PcapPro extends NonSealedPcap implements CaptureStatistics {

	/**
	 * Create a live capture handle.
	 * 
	 * {@code create} is used to create a packet capture handle to look at packets
	 * on the network. source is a string that specifies the network device to open;
	 * on Linux systems with 2.2 or later kernels, a source argument of "any" or
	 * NULL can be used to capture packets from all interfaces. The returned handle
	 * must be activated with pcap_activate() before pack' ets can be captured with
	 * it; options for the capture, such as promiscu' ous mode, can be set on the
	 * handle before activating it.
	 *
	 * @param device pcap network interface that specifies the network device to
	 *               open.
	 * @return a new pcap object that needs to be activated using
	 *         {@link #activate()} call
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public static PcapPro create(PcapIf device) throws PcapException {
		return Pcap1_0.create(PcapPro::new, device.name());
	}

	/**
	 * Create a live capture handle.
	 * 
	 * {@code create} is used to create a packet capture handle to look at packets
	 * on the network. source is a string that specifies the network device to open;
	 * on Linux systems with 2.2 or later kernels, a source argument of "any" or
	 * NULL can be used to capture packets from all interfaces. The returned handle
	 * must be activated with pcap_activate() before pack' ets can be captured with
	 * it; options for the capture, such as promiscu' ous mode, can be set on the
	 * handle before activating it.
	 *
	 * @param device a string that specifies the network device to open; on Linux
	 *               systems with 2.2 or later kernels, a source argument of "any"
	 *               or NULL can be used to capture packets from all interfaces.
	 * @return a new pcap object that needs to be activated using
	 *         {@link #activate()} call
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public static PcapPro create(String device) throws PcapException {
		return Pcap1_9.create(PcapPro::new, device);
	}

	/**
	 * Open a fake pcap_t for compiling filters or opening a capture for output.
	 *
	 * <p>
	 * {@link #openDead} and pcap_open_dead_with_tstamp_precision() are used for
	 * creating a pcap_t structure to use when calling the other functions in
	 * libpcap. It is typically used when just using libpcap for compiling BPF full;
	 * it can also be used if using pcap_dump_open(3PCAP), pcap_dump(3PCAP), and
	 * pcap_dump_close(3PCAP) to write a savefile if there is no pcap_t that
	 * supplies the packets to be written.
	 * </p>
	 * 
	 * <p>
	 * When pcap_open_dead_with_tstamp_precision(), is used to create a pcap_t for
	 * use with pcap_dump_open(), precision specifies the time stamp precision for
	 * packets; PCAP_TSTAMP_PRECISION_MICRO should be specified if the packets to be
	 * written have time stamps in seconds and microseconds, and
	 * PCAP_TSTAMP_PRECISION_NANO should be specified if the packets to be written
	 * have time stamps in seconds and nanoseconds. Its value does not affect
	 * pcap_compile(3PCAP).
	 * </p>
	 * 
	 * @param linktype specifies the link-layer type for the pcap handle
	 * @param snaplen  specifies the snapshot length for the pcap handle
	 * @return A dead pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.6
	 */
	public static PcapPro openDead(PcapDlt linktype, int snaplen) throws PcapException {
		return Pcap0_6.openDead(PcapPro::new, linktype, snaplen);
	}

	/**
	 * Open a fake pcap_t for compiling filters or opening a capture for output.
	 * 
	 * <p>
	 * {@link #openDead(PcapDlt, int)} and
	 * {@link #openDeadWithTstampPrecision(PcapDlt, int, PcapTStampPrecision)} are
	 * used for creating a pcap_t structure to use when calling the other functions
	 * in libpcap. It is typically used when just using libpcap for compiling BPF
	 * full; it can also be used if using {@code #dumpOpen(String)},
	 * {@link PcapDumper#dump(MemoryAddress, MemoryAddress)}, and
	 * {@link PcapDumper#close()} to write a savefile if there is no pcap_t that
	 * supplies the packets to be written.
	 * </p>
	 * 
	 * <p>
	 * When {@link #openDeadWithTstampPrecision(PcapDlt, int, PcapTStampPrecision)},
	 * is used to create a {@code Pcap} handle for use with
	 * {@link #dumpOpen(String)}, precision specifies the time stamp precision for
	 * packets; PCAP_TSTAMP_PRECISION_MICRO should be specified if the packets to be
	 * written have time stamps in seconds and microseconds, and
	 * PCAP_TSTAMP_PRECISION_NANO should be specified if the packets to be written
	 * have time stamps in seconds and nanoseconds. Its value does not affect
	 * pcap_compile(3PCAP).
	 * </p>
	 *
	 * @param linktype  specifies the link-layer type for the pcap handle
	 * @param snaplen   specifies the snapshot length for the pcap handle
	 * @param precision the requested timestamp precision
	 * @return A dead pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 1.5.1
	 */
	public static PcapPro openDeadWithTstampPrecision(PcapDlt linktype, int snaplen, PcapTStampPrecision precision)
			throws PcapException {
		return Pcap1_5.openDeadWithTstampPrecision(PcapPro::new, linktype, snaplen, precision);
	}

	/**
	 * Open a device for capturing.
	 * 
	 * <p>
	 * {@code openLive} is used to obtain a packet capture handle to look at packets
	 * on the network. device is a string that specifies the network device to open;
	 * on Linux systems with 2.2 or later kernels, a device argument of "any" or
	 * NULL can be used to capture packets from all interfaces.
	 * </p>
	 *
	 * @param device  the device name
	 * @param snaplen specifies the snapshot length to be set on the handle
	 * @param promisc specifies whether the interface is to be put into promiscuous
	 *                mode. If promisc is non-zero, promiscuous mode will be set,
	 *                otherwise it will not be set
	 * @param timeout the packet buffer timeout, as a non-negative value, in units
	 * @param unit    time timeout unit
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.4
	 */
	public static PcapPro openLive(PcapIf device,
			int snaplen,
			boolean promisc,
			long timeout,
			TimeUnit unit) throws PcapException {

		return Pcap0_4.openLive(PcapPro::new, device.name(), snaplen, promisc, timeout, unit);
	}

	/**
	 * Open a device for capturing.
	 * 
	 * <p>
	 * {@code openLive} is used to obtain a packet capture handle to look at packets
	 * on the network. device is a string that specifies the network device to open;
	 * on Linux systems with 2.2 or later kernels, a device argument of "any" or
	 * NULL can be used to capture packets from all interfaces.
	 * </p>
	 *
	 * @param device  the device name
	 * @param snaplen specifies the snapshot length to be set on the handle
	 * @param promisc specifies whether the interface is to be put into promiscuous
	 *                mode. If promisc is non-zero, promiscuous mode will be set,
	 *                otherwise it will not be set
	 * @param timeout the packet buffer timeout, as a non-negative value, in units
	 * @param unit    time timeout unit
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.4
	 */
	public static PcapPro openLive(String device,
			int snaplen,
			boolean promisc,
			long timeout,
			TimeUnit unit) throws PcapException {

		return Pcap0_4.openLive(PcapPro::new, device, snaplen, promisc, timeout, unit);
	}

	/**
	 * Open a saved capture file for reading.
	 * 
	 * <p>
	 * pcap_open_offline() and pcap_open_offline_with_tstamp_precision() are called
	 * to open a ``savefile'' for reading.
	 * </p>
	 *
	 * @param file the offline capture file
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.4
	 */
	public static PcapPro openOffline(File file) throws PcapException {
		return Pcap0_4.openOffline(PcapPro::new, file.getAbsolutePath());
	}

	/**
	 * Open a saved capture file for reading.
	 * 
	 * <p>
	 * pcap_open_offline() and pcap_open_offline_with_tstamp_precision() are called
	 * to open a ``savefile'' for reading.
	 * </p>
	 *
	 * @param fname specifies the name of the file to open. The file can have the
	 *              pcap file format as described in pcap-savefile(5), which is the
	 *              file format used by, among other programs, tcpdump(1) and
	 *              tcpslice(1), or can have the pcapng file format, although not
	 *              all pcapng files can be read
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.4
	 */
	public static PcapPro openOffline(String fname) throws PcapException {
		return Pcap0_4.openOffline(PcapPro::new, fname);
	}

	/** The ipf config. */
	private final PacketDispatcherConfig config = new PacketDispatcherConfig();
	private CaptureStatistics stats = new CaptureStatisticsImpl();

	/** The packet dispatcher. */
	private final MainPacketDispatcher postProcessorRoot;
	private PacketDispatcher postProcessor;

	private final PcapDispatcher preProcessorRoot;
	private PcapDispatcher preProcessor;

	private final Stack<PcapConfigurator<?>> preProcessors = new Stack<>();
	private final Stack<PcapConfigurator<?>> postProcessors = new Stack<>();

	private boolean isActive;

	/**
	 * Instantiates a new pcap pro.
	 *
	 * @param pcapHandle the pcap handle
	 * @param name       the name
	 * @param abi        the abi
	 */
	PcapPro(MemoryAddress pcapHandle, String name, PcapHeaderABI abi) {
		super(pcapHandle, name, abi);
		config.abi = abi;

		this.preProcessorRoot = new StandardPcapDispatcher(pcapHandle, abi, this::breakloop);
		this.preProcessor = this.preProcessorRoot;
		this.postProcessorRoot = new MainPacketDispatcher(config);
		this.postProcessor = postProcessorRoot;

		postProcessorRoot.setPcapDispatcher(preProcessor);

		setDescriptorType(PacketDescriptorType.TYPE2);
	}

	@Override
	public void activate() throws PcapException {
		if (isActive)
			throw new PcapActivatedException(PcapCode.PCAP_ERROR_ACTIVATED, "pcap-pro handle already active");

		try {
			super.activate();
		} catch (PcapActivatedException e) {} // Offline/dead handles are active already

		try {
			installAllPreProcessors();
			installMainPacketProcessor();
			installAllPostProcessors();
		} finally {
			this.isActive = true;
		}
	}

	private void checkIfActive() throws IllegalStateException {
		if (!isActive)
			throw new IllegalStateException("inactive - must use Pcap.activate()");
	}

	private void checkIfInactive() throws IllegalStateException {
		if (isActive)
			throw new IllegalStateException("handle already active");
	}

	/**
	 * Dispatch which uses a simple packet consumer.
	 *
	 * @param count          A value of -1 or 0 for count is equivalent to infinity,
	 *                       so that packets are processed until another ending
	 *                       condition occurs
	 * @param packetConsumer the packet consumer
	 * @return returns 0 if count is exhausted or if, when reading from a
	 *         ``savefile'', no more packets are available. It returns
	 *         PCAP_ERROR_BREAK if the loop terminated due to a call to
	 *         pcap_breakloop() before any packets were processed
	 */
	public int dispatch(int count, OfPacketConsumer packetConsumer) {
		return dispatch(count, (u, p) -> packetConsumer.accept(p), 0);
	}

	/**
	 * Process packets from a live capture or savefile.
	 * <p>
	 * pcap_loop() processes packets from a live capture or ``savefile'' until cnt
	 * packets are processed, the end of the ``savefile'' is reached when reading
	 * from a ``savefile'', pcap_breakloop(3PCAP) is called, or an error occurs. It
	 * does not return when live packet buffer timeouts occur. A value of -1 or 0
	 * for cnt is equivalent to infinity, so that packets are processed until
	 * another ending condition occurs.
	 * </p>
	 * <p>
	 * Note that, when doing a live capture on some platforms, if the read timeout
	 * expires when there are no packets available, pcap_dispatch() will return 0,
	 * even when not in non-blocking mode, as there are no packets to process.
	 * Applications should be prepared for this to happen, but must not rely on it
	 * happening.
	 * </p>
	 * <p>
	 * callback specifies a pcap_handler routine to be called with three arguments:
	 * a u_char pointer which is passed in the user argument to pcap_loop() or
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer pointing to the packet
	 * time stamp and lengths, and a const u_char pointer to the first caplen (as
	 * given in the struct pcap_pkthdr a pointer to which is passed to the callback
	 * routine) bytes of data from the packet. The struct pcap_pkthdr and the packet
	 * data are not to be freed by the callback routine, and are not guaranteed to
	 * be valid after the callback routine returns; if the full needs them to be
	 * valid after the callback, it must make a copy of them.
	 * </p>
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * pcap_datalink(3PCAP) routine when handed the pcap_t value also passed to
	 * pcap_loop() or pcap_dispatch(). https://www.tcpdump.org/linktypes.html lists
	 * the values pcap_datalink() can return and describes the packet formats that
	 * correspond to those values. The value it returns will be valid for all
	 * packets received unless and until pcap_set_datalink(3PCAP) is called; after a
	 * successful call to pcap_set_datalink(), all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to pcap_set_datalink().
	 * </p>
	 * <p>
	 * Do NOT assume that the packets for a given capture or ``savefile`` will have
	 * any given link-layer header type, such as DLT_EN10MB for Ethernet. For
	 * example, the "any" device on Linux will have a link-layer header type of
	 * DLT_LINUX_SLL or DLT_LINUX_SLL2 even if all devices on the system at the time
	 * the "any" device is opened have some other data link type, such as DLT_EN10MB
	 * for Ethernet.
	 * </p>
	 *
	 * @param <U>     the generic type
	 * @param count   A value of -1 or 0 for count is equivalent to infinity, so
	 *                that packets are processed until another ending condition
	 *                occurs
	 * @param handler array handler which will receive packets
	 * @param user    the user
	 * @return returns 0 if count is exhausted or if, when reading from a
	 *         ``savefile'', no more packets are available. It returns
	 *         PCAP_ERROR_BREAK if the loop terminated due to a call to
	 *         pcap_breakloop() before any packets were processed
	 * @since libpcap 0.4
	 */
	public <U> int dispatch(int count, PcapProHandler.OfPacket<U> handler, U user) {
		checkIfActive();

		return postProcessor.dispatchPacket(count, handler, user);
	}

	/**
	 * Dispatch which uses a simple packet consumer.
	 *
	 * @param packetConsumer the packet consumer
	 * @return returns 0 if count is exhausted or if, when reading from a
	 *         ``savefile'', no more packets are available. It returns
	 *         PCAP_ERROR_BREAK if the loop terminated due to a call to
	 *         pcap_breakloop() before any packets were processed
	 */
	public int dispatch(OfPacketConsumer packetConsumer) {
		return dispatch(0, (u, p) -> packetConsumer.accept(p), 0);
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.CaptureStatistics#getDroppedCaplenCount()
	 */
	@Override
	public long getDroppedCaplenCount() {
		return stats.getDroppedCaplenCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.CaptureStatistics#getDroppedPacketCount()
	 */
	@Override
	public long getDroppedPacketCount() {
		return stats.getDroppedPacketCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.CaptureStatistics#getDroppedWirelenCount()
	 */
	@Override
	public long getDroppedWirelenCount() {
		return stats.getDroppedWirelenCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.CaptureStatistics#getReceivedCaplenCount()
	 */
	@Override
	public long getReceivedCaplenCount() {
		return stats.getReceivedCaplenCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.CaptureStatistics#getReceivedPacketCount()
	 */
	@Override
	public long getReceivedPacketCount() {
		return stats.getReceivedPacketCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.CaptureStatistics#getReceivedWirelenCount()
	 */
	@Override
	public long getReceivedWirelenCount() {
		return stats.getReceivedWirelenCount();
	}

	/**
	 * Gets any uncaught exceptions.
	 *
	 * @return the uncaught exception
	 */
	public Optional<Throwable> getUncaughtException() {
		return Optional.ofNullable(preProcessor.getUncaughtException());
	}

	public <T extends PostProcessor> T installFactory(PostFactory<T> postProcessorSupplier) {
		checkIfInactive();

		return install(postProcessorSupplier.newInstance());
	}

	public <T extends PreProcessor> T installFactory(PreFactory<T> preProcessorSupplier) {
		checkIfInactive();

		return install(preProcessorSupplier.newInstance());
	}

	public <T extends PostProcessor> T install(T postProcessor) {
		checkIfInactive();

		if (!(postProcessor instanceof PcapConfigurator<?> processor))
			throw new IllegalArgumentException("invalid post-processor [%s]"
					.formatted(postProcessor.getClass()));

		postProcessors.push(processor);

		return postProcessor;
	}

	public <T extends PreProcessor> T install(T preProcessor) {
		checkIfInactive();

		if (!(preProcessor instanceof PcapConfigurator<?> processor))
			throw new IllegalArgumentException("invalid pre-processor [%s]"
					.formatted(preProcessor.getClass()));

		preProcessors.push(processor);

		return preProcessor;
	}

	private void installAllPostProcessors() {
		postProcessors.stream()
				.filter(c -> c.isEnabled())
				.forEach(this::installPostProcessor);
	}

	private void installAllPreProcessors() {
		preProcessors.stream()
				.filter(c -> c.isEnabled())
				.forEach(this::installPreProcessor);
	}

	private void installMainPacketProcessor() {
		/*
		 * Main processor already created, we just need to connect it up the pcap
		 * dispatchers (ie. PreProcessors) that are already installed and configured.
		 */
		postProcessorRoot.setPcapDispatcher(preProcessor);
	}

	private void installPostProcessor(PcapConfigurator<?> processor) {
		this.postProcessor = processor.newDispatcherInstance(preProcessor, postProcessor);
	}

	private void installPreProcessor(PcapConfigurator<?> processor) {
		this.preProcessor = processor.newDispatcherInstance(this.preProcessor);
	}

	/**
	 * Process packets from a live capture or savefile.
	 *
	 * @param count          A value of -1 or 0 for count is equivalent to infinity,
	 *                       so that packets are processed until another ending
	 *                       condition occurs
	 * @param packetConsumer the packet consumer
	 * @return returns 0 if count is exhausted or if, when reading from a
	 *         ``savefile'', no more packets are available. It returns
	 *         PCAP_ERROR_BREAK if the loop terminated due to a call to
	 *         pcap_breakloop() before any packets were processed
	 */
	public int loop(int count, OfPacketConsumer packetConsumer) {
		checkIfActive();

		return loop(count, (u, p) -> packetConsumer.accept(p), 0);
	}

	/**
	 * Process packets from a live capture or savefile.
	 * <p>
	 * pcap_loop() processes packets from a live capture or ``savefile'' until cnt
	 * packets are processed, the end of the ``savefile'' is reached when reading
	 * from a ``savefile'', pcap_breakloop(3PCAP) is called, or an error occurs. It
	 * does not return when live packet buffer timeouts occur. A value of -1 or 0
	 * for cnt is equivalent to infinity, so that packets are processed until
	 * another ending condition occurs.
	 * </p>
	 * <p>
	 * Note that, when doing a live capture on some platforms, if the read timeout
	 * expires when there are no packets available, pcap_dispatch() will return 0,
	 * even when not in non-blocking mode, as there are no packets to process.
	 * Applications should be prepared for this to happen, but must not rely on it
	 * happening.
	 * </p>
	 * <p>
	 * callback specifies a pcap_handler routine to be called with three arguments:
	 * a u_char pointer which is passed in the user argument to pcap_loop() or
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer pointing to the packet
	 * time stamp and lengths, and a const u_char pointer to the first caplen (as
	 * given in the struct pcap_pkthdr a pointer to which is passed to the callback
	 * routine) bytes of data from the packet. The struct pcap_pkthdr and the packet
	 * data are not to be freed by the callback routine, and are not guaranteed to
	 * be valid after the callback routine returns; if the full needs them to be
	 * valid after the callback, it must make a copy of them.
	 * </p>
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * pcap_datalink(3PCAP) routine when handed the pcap_t value also passed to
	 * pcap_loop() or pcap_dispatch(). https://www.tcpdump.org/linktypes.html lists
	 * the values pcap_datalink() can return and describes the packet formats that
	 * correspond to those values. The value it returns will be valid for all
	 * packets received unless and until pcap_set_datalink(3PCAP) is called; after a
	 * successful call to pcap_set_datalink(), all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to pcap_set_datalink().
	 * </p>
	 * <p>
	 * Do NOT assume that the packets for a given capture or ``savefile`` will have
	 * any given link-layer header type, such as DLT_EN10MB for Ethernet. For
	 * example, the "any" device on Linux will have a link-layer header type of
	 * DLT_LINUX_SLL or DLT_LINUX_SLL2 even if all devices on the system at the time
	 * the "any" device is opened have some other data link type, such as DLT_EN10MB
	 * for Ethernet.
	 * </p>
	 *
	 * @param <U>     the generic type
	 * @param count   A value of -1 or 0 for count is equivalent to infinity, so
	 *                that packets are processed until another ending condition
	 *                occurs
	 * @param handler array handler which will receive packets
	 * @param user    the user
	 * @return returns 0 if count is exhausted or if, when reading from a
	 *         ``savefile'', no more packets are available. It returns
	 *         PCAP_ERROR_BREAK if the loop terminated due to a call to
	 *         pcap_breakloop() before any packets were processed
	 * @since libpcap 0.4
	 */
	public <U> int loop(int count, PcapProHandler.OfPacket<U> handler, U user) {
		return postProcessor.loopPacket(count, handler, user);
	}

	/**
	 * @see org.jnetpcap.Pcap0_4#next()
	 */
	@Override
	public PcapPacketRef next() throws PcapException {
		return preProcessor.next();
	}

	/**
	 * @see org.jnetpcap.Pcap0_8#nextEx()
	 */
	@Override
	public PcapPacketRef nextEx() throws PcapException, TimeoutException {
		return preProcessor.nextEx();
	}

	/**
	 * Read the next packet from a pcap handle.
	 * <p>
	 * reads the next packet and returns a success/failure indication. If the packet
	 * was read without problems, the pointer pointed to by the pktHeader argument
	 * is set to point to the pcap_pkthdr struct for the packet, and the pointer
	 * pointed to by the pktData argument is set to point to the data in the packet.
	 * The struct pcap_pkthdr and the packet data are not to be freed by the caller,
	 * and are not guaranteed to be valid after the next call to {@link #nextEx},
	 * {@link #next}, {@link #loop}, or {@link #dispatch}; if the full needs them to
	 * remain valid, it must make a copy of them. *
	 * </p>
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * {@code datalink} routine when handed the pcap_t value also passed to
	 * {@code loop} or {@code dispatch}. https://www.tcpdump.org/linktypes.html
	 * lists the values {@code datalink} can return and describes the packet formats
	 * that correspond to those values. The value it returns will be valid for all
	 * packets received unless and until {@code setDatalink} is called; after a
	 * successful call to {@code setDatalink}, all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to {@code setDatalink}.
	 * </p>
	 * <p>
	 * Do NOT assume that the packets for a given capture or ``savefile`` will have
	 * any given link-layer header type, such as DLT_EN10MB for Ethernet. For
	 * example, the "any" device on Linux will have a link-layer header type of
	 * DLT_LINUX_SLL or DLT_LINUX_SLL2 even if all devices on the system at the time
	 * the "any" device is opened have some other data link type, such as DLT_EN10MB
	 * for Ethernet.
	 * </p>
	 *
	 * @return a native pcap packet reference or null if packets are being read from
	 *         a ``savefile'' and there are no more packets to read from the
	 *         savefile.
	 * @throws PcapException    any pcap errors such as not activated, etc.
	 * @throws TimeoutException if packets are being read from a live capture and
	 *                          the packet buffer timeout expired
	 * @since Pcap 0.8
	 */
	public Packet nextExPacket() throws PcapException, TimeoutException {
		return postProcessor.nextExPacket();
	}

	/**
	 * read the next packet from a handle.
	 * 
	 * <p>
	 * reads the next packet (by calling dispatch with a cnt of 1) and returns a
	 * u_char pointer to the data in that packet. The packet data is not to be freed
	 * by the caller, and is not guaranteed to be valid after the next call to
	 * nextEx, next, loop, or dispatch; if the full needs it to remain valid, it
	 * must make a copy of it. The pcap_pkthdr structure pointed to by h is filled
	 * in with the appropriate values for the packet.
	 * </p>
	 * 
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * {@code datalink} routine when handed the pcap_t value also passed to
	 * {@code loop} or {@code dispatch}. https://www.tcpdump.org/linktypes.html
	 * lists the values {@code datalink} can return and describes the packet formats
	 * that correspond to those values. The value it returns will be valid for all
	 * packets received unless and until {@code setDatalink} is called; after a
	 * successful call to {@code setDatalink}, all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to {@code setDatalink}.
	 * </p>
	 * 
	 * <p>
	 * Do NOT assume that the packets for a given capture or ``savefile`` will have
	 * any given link-layer header type, such as DLT_EN10MB for Ethernet. For
	 * example, the "any" device on Linux will have a link-layer header type of
	 * DLT_LINUX_SLL or DLT_LINUX_SLL2 even if all devices on the system at the time
	 * the "any" device is opened have some other data link type, such as DLT_EN10MB
	 * for Ethernet.
	 * </p>
	 *
	 * @return a pointer to the packet data on success, and returns NULL if no
	 *         packets were read from a live capture (if, for example, they were
	 *         discarded because they didn't pass the packet filter, or if, on
	 *         platforms that support a packet buffer timeout that starts before any
	 *         packets arrive, the timeout expires before any packets arrive, or if
	 *         the file descriptor for the capture device is in non-blocking mode
	 *         and no packets were available to be read), or if no more packets are
	 *         available in a ``savefile.'' Unfortunately, there is no way to
	 *         determine whether an error occurred or not.
	 * @throws PcapException Unfortunately, there is no way to determine whether an
	 *                       error occurred or not so exception may be due to no
	 *                       packets being captured and not an actual error.
	 * @since libpcap 0.4
	 */
	public Packet nextPacket() throws PcapException {
		return postProcessor.nextPacket();
	}

	/**
	 * Sets the descriptor type.
	 *
	 * @param type the type
	 * @return the pcap pro
	 */
	public PcapPro setDescriptorType(PacketDescriptorType type) {
		config.descriptorType = type;
		config.dissector = PacketDissector.dissector(type);

		this.stats = postProcessorRoot.getCaptureStatistics();

		return this;
	}

	/**
	 * Sets the frame number.
	 *
	 * @param frameNumberAssigner the frame number assigner
	 * @return the pcap pro
	 */
	public PcapPro setFrameNumber(FrameNumber frameNumberAssigner) {
		config.frameNo = frameNumberAssigner;

		return this;
	}

	/**
	 * Sets the frame starting number.
	 *
	 * @param startingNo the starting no
	 * @return the pcap pro
	 */
	public PcapPro setFrameStartingNumber(long startingNo) {
		return setFrameNumber(FrameNumber.starting(startingNo));
	}

	/**
	 * Sets the packet formatter.
	 *
	 * @param formatter the formatter
	 * @return the pcap pro
	 */
	public PcapPro setPacketFormatter(PacketFormat formatter) {
		config.formatter = formatter;

		return this;
	}

	/**
	 * Sets the port number.
	 *
	 * @param portNo the port no
	 * @return the pcap pro
	 */
	public PcapPro setPortNumber(int portNo) {
		config.portNo = portNo;

		return this;
	}

	/**
	 * Sets the timestamp unit which specifies the timestamp used by this pcap
	 * handle.
	 *
	 * @param unit the new timestamp unit
	 * @return this pcap
	 */
	public PcapPro setTimestampUnit(TimestampUnit unit) {
		config.timestampUnit = unit;

		return this;
	}

	/**
	 * Sets the uncaught exception handler.
	 *
	 * @param exceptionHandler the exception handler
	 * @return the pcap
	 */
	@Override
	public final PcapPro setUncaughtExceptionHandler(Consumer<? super Throwable> exceptionHandler) {
		return setUncaughtExceptionHandler((t, e) -> exceptionHandler.accept(e));
	}

	/**
	 * Sets the uncaught exception handler.
	 *
	 * @param exceptionHandler the exception handler
	 * @return the pcap pro
	 * @see org.jnetpcap.Pcap#setUncaughtExceptionHandler(java.lang.Thread.UncaughtExceptionHandler)
	 */
	@Override
	public final PcapPro setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		super.setUncaughtExceptionHandler(exceptionHandler);

		return this;
	}

	/**
	 * Uninstall selectively pre or post packet processors. The processors are
	 * removed from the install queues and will not be installed at the time of
	 * activation.
	 *
	 * @param preProcessors  the pre processors
	 * @param postProcessors the post processors
	 * @return the pcap pro
	 */
	public PcapPro uninstall(boolean preProcessors, boolean postProcessors) {
		checkIfInactive();

		if (preProcessors)
			this.preProcessors.clear();

		if (postProcessors)
			this.postProcessors.clear();

		return this;
	}

	/**
	 * Uninstall all pre and post packet processors. The processors are removed from
	 * the installation queues and will not be installed at the time of activation.
	 *
	 * @return reference to this pcap handle
	 */
	public PcapPro uninstallAll() {
		checkIfInactive();

		return uninstall(true, true);
	}

	public boolean isOfflineCapture() {
		return libVersion() != null;
	}

	public boolean isLiveCapture() {
		return !isOfflineCapture();
	}

}
