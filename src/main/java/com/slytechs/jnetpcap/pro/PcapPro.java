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
import java.util.function.Consumer;

import org.jnetpcap.Pcap0_4;
import org.jnetpcap.Pcap0_6;
import org.jnetpcap.Pcap1_0;
import org.jnetpcap.Pcap1_5;
import org.jnetpcap.Pcap1_9;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapIf;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapTStampPrecision;
import org.jnetpcap.internal.NonSealedPcap;
import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.internal.StandardPcapDispatcher;

import com.slytechs.jnetpcap.pro.PacketProcessor.PostProcessor;
import com.slytechs.jnetpcap.pro.PacketProcessor.PostProcessor.PostFactory;
import com.slytechs.jnetpcap.pro.PacketProcessor.PreProcessor;
import com.slytechs.jnetpcap.pro.PacketProcessor.PreProcessor.PreFactory;
import com.slytechs.jnetpcap.pro.PcapProHandler.OfPacketConsumer;
import com.slytechs.jnetpcap.pro.internal.PacketDispatcherJava;
import com.slytechs.jnetpcap.pro.internal.PacketStatisticsImpl;
import com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig;
import com.slytechs.jnetpcap.pro.internal.ipf.IpfPostProcessor;
import com.slytechs.jnetpcap.pro.internal.ipf.IpfPostProcessorJava;
import com.slytechs.protocol.Frame.FrameNumber;
import com.slytechs.protocol.descriptor.PacketDissector;
import com.slytechs.protocol.meta.PacketFormat;
import com.slytechs.protocol.pack.core.constants.PacketDescriptorType;
import com.slytechs.protocol.runtime.time.TimestampSource;
import com.slytechs.protocol.runtime.time.TimestampUnit;
import com.slytechs.protocol.runtime.util.CountUnit;
import com.slytechs.protocol.runtime.util.MemoryUnit;

/**
 * Pcap packet capture with high level packet and protocol support.
 * 
 * <h2>IPF Modes</h2> The pro pcap API provides support for IP fragment
 * reassembly and tracking. When enabled, the user packet handler will receive
 * fully reassembled IP datagrams instead of individual fragments along with any
 * other type of packets selected by the packet filter applied.
 * <p>
 * To enable IPF mode, use the fluent method {@link #enableIpf(boolean)} before
 * the pcap handle is activated. Once enabled, numerous defaults are used and
 * can be changed by the use of the pcap handle. By default, IPF tracking and
 * reassembly are both enabled. Of course these settings can be changed by use
 * of {@link #enableIpfTracking(boolean)} and
 * {@link #enableIpfReassembly(boolean)} respectively. Further more, IPF
 * reassembly can be configured to attach IPF reassembled buffer to the last IP
 * fragment and/or inserted as a new IP data-gram into the dispatcher's packet
 * stream. This way the user packet handler will receive fully reassembled IP
 * datagrams as packets. The default is to not forward individual IP fragments,
 * but deliver the fully reassembled IP data-gram as a new packet, containing
 * all of the IP fragment data combined.
 * </p>
 * <p>
 * If you would like to receive all of the IP fragments used in the reassembly
 * as well, use the method {@link #enableIpfPassthrough(boolean)} which will
 * cause all of the IP fragments to be passed through in their original form.
 * </p>
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public final class PcapPro extends NonSealedPcap implements IpfConfiguration, PacketStatistics {

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
	private final IpfConfig ipfConfig = new IpfConfig();
	private PacketStatistics stats = new PacketStatisticsImpl();

	/** The packet dispatcher. */
	private PacketDispatcherJava postProcessorCommon;

	private final PcapDispatcher preProcessorRoot;
	private PcapDispatcher preProcessor;

	private final Stack<PacketProcessor<?>> preProcessors = new Stack<>();
	private final Stack<PacketProcessor<?>> postProcessors = new Stack<>();

	public <T extends PostProcessor> T install(PostFactory<T> factory) {
		return null;
	}

	public <T extends PreProcessor> T install(PreFactory<T> factory) {

		T preProcessor = factory.newInstance(this::installPreProcessor);

		return preProcessor;
	}

	private void installPreProcessor(PreProcessor preProcessor) {
		if (!(preProcessor instanceof PacketProcessor<?> processor))
			throw new IllegalArgumentException("invalid pre-processor [%s]"
					.formatted(preProcessor.getClass()));

		preProcessors.push(processor);

		this.preProcessor = processor.newInstance(this.preProcessor);
	}

	public <T extends PacketProcessor<T> & PostProcessor> T postInstall(T postProcessor) {
		postProcessors.push(postProcessor);

		return postProcessor;
	}

	/**
	 * Instantiates a new pcap pro.
	 *
	 * @param pcapHandle the pcap handle
	 * @param name       the name
	 * @param abi        the abi
	 */
	PcapPro(MemoryAddress pcapHandle, String name, PcapHeaderABI abi) {
		super(pcapHandle, name, abi);
		ipfConfig.abi = abi;

		this.preProcessorRoot = new StandardPcapDispatcher(pcapHandle, this::breakloop);
		this.preProcessor = this.preProcessorRoot;

		setDescriptorType(PacketDescriptorType.TYPE2);

		enableIpf(isIpfEnabled());
	}

	@Override
	public void activate() throws PcapException {
		super.activate();

		activateIpfIfNeeded();
	}

	public PcapPro activateIpf() {
		checkIpfIsNotActive();

		activateIpfIfNeeded();

		return this;
	}

	private PcapPro activateIpfIfNeeded() {

		if (ipfConfig.isIpfEnabled() && !(postProcessorCommon instanceof IpfPostProcessor)) {
			var ipf = new IpfPostProcessorJava(
					ipfConfig);
			ipf.setPcapDispatcher(preProcessor);

			this.postProcessorCommon = ipf;
		}

		this.stats = postProcessorCommon.getPacketStatistics();

		return this;
	}

	private void checkIpfIsNotActive() throws IllegalStateException {
		if (ipfConfig.isIpfEnabled() && postProcessorCommon instanceof IpfPostProcessor)
			throw new IllegalStateException("IPF already active");
	}

	/**
	 * Disable native IP fragment tracking and reassembly. By default, the native
	 * IPF tracking and reassembly is used, if native library is available. This
	 * option, disables the use of native IPF, even if available.
	 * 
	 * <p>
	 * This option has no effect if native library is not available (ie. found on
	 * java.library.path).
	 * </p>
	 *
	 * @param enable if true, native IPF will be disabled even if available (native
	 *               library found), otherwise if false, native implementation will
	 *               be preferred, if native library is available.
	 * @return this handle
	 */
	public PcapPro disableNativeIpf(boolean enable) {
		throw new UnsupportedOperationException("Not implemented yet. ");
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
		return postProcessorCommon.dispatchPacket(count, handler, user);
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
	 * Drop reassembled ip fragments. IP fragments are dropped before being
	 * dispatched to the dispatcher. If IPF reassembly is enabled, that fragments
	 * are used to reasseble IP datagrams and dropped after wards. If IP
	 * fragmentation is disabled and fragments to be dropped, a specialized capture
	 * will be set to drop fragments at the capture interface level.
	 *
	 * @param enable true enables IP fragment to be dropped
	 * @return this handle
	 */
	public PcapPro dropReassembledIpFragments(boolean enable) {
		throw new UnsupportedOperationException("Not implemented yet. ");
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpf(boolean)
	 */
	@Override
	public PcapPro enableIpf(boolean enable) {
		checkIpfIsNotActive();

		ipfConfig.enableIpf(enable);

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfAttachComplete(boolean)
	 */
	@Override
	public PcapPro enableIpfAttachComplete(boolean ipfAttachComplete) {
		checkIpfIsNotActive();

		ipfConfig.enableIpfAttachComplete(ipfAttachComplete);

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfAttachIncomplete(boolean)
	 */
	@Override
	public PcapPro enableIpfAttachIncomplete(boolean ipfAttachIncomplete) {
		checkIpfIsNotActive();

		ipfConfig.enableIpfAttachIncomplete(ipfAttachIncomplete);

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfFragments(boolean)
	 */
	@Override
	public PcapPro enableIpfFragments(boolean passFragments) {
		checkIpfIsNotActive();

		ipfConfig.enableIpfFragments(passFragments);

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfIncomplete(boolean)
	 */
	@Override
	public PcapPro enableIpfIncomplete(boolean passDgramsIncomplete) {
		checkIpfIsNotActive();

		ipfConfig.enableIpfIncomplete(passDgramsIncomplete);

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfPassComplete(boolean)
	 */
	@Override
	public PcapPro enableIpfPassComplete(boolean passDgramsComplete) {
		checkIpfIsNotActive();

		ipfConfig.enableIpfPassComplete(passDgramsComplete);

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfPassthrough(boolean)
	 */
	@Override
	public PcapPro enableIpfPassthrough(boolean enable) {
		checkIpfIsNotActive();

		ipfConfig.enableIpfPassthrough(enable);

		return this;
	}

	/**
	 * Enable IP datagram reassembly using IP fragments. IP fragments are tracked
	 * and reassembled into new data buffers and dispatched as new packets to use
	 * handler.
	 *
	 * @param enable if true, enable IP datagram reassembly.
	 * @return this handle
	 */
	@Override
	public PcapPro enableIpfReassembly(boolean enable) {
		checkIpfIsNotActive();

		ipfConfig.enableIpfReassembly(enable);

		return this;
	}

	/**
	 * Enable IP fragment tracking. When IP fragment tracking is enabled, IP
	 * fragments are tracked in IPF Table and dispatched with a specialized IPF
	 * descriptor with tracking information.
	 *
	 * @param enable if true, enable IP fragment tracking
	 * @return this handle
	 */
	@Override
	public PcapPro enableIpfTracking(boolean enable) {
		checkIpfIsNotActive();

		ipfConfig.enableIpfTracking(enable);

		return this;
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.PacketStatistics#getDroppedCaplenCount()
	 */
	@Override
	public long getDroppedCaplenCount() {
		return stats.getDroppedCaplenCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.PacketStatistics#getDroppedPacketCount()
	 */
	@Override
	public long getDroppedPacketCount() {
		return stats.getDroppedPacketCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.PacketStatistics#getDroppedWirelenCount()
	 */
	@Override
	public long getDroppedWirelenCount() {
		return stats.getDroppedWirelenCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#getIpfBufferSize()
	 */
	@Override
	public int getIpfBufferSize() {
		return ipfConfig.getIpfBufferSize();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#getIpfMaxDgramBytes()
	 */
	@Override
	public int getIpfMaxDgramBytes() {
		return ipfConfig.getIpfMaxDgramBytes();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#getIpfMaxFragmentCount()
	 */
	@Override
	public int getIpfMaxFragmentCount() {
		return ipfConfig.getIpfMaxFragmentCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#getIpfTableSize()
	 */
	@Override
	public int getIpfTableSize() {
		return ipfConfig.getIpfTableSize();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#getTimeoutMilli()
	 */
	@Override
	public long getIpfTimeoutMilli() {
		return ipfConfig.getIpfTimeoutMilli();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.PacketStatistics#getReceivedCaplenCount()
	 */
	@Override
	public long getReceivedCaplenCount() {
		return stats.getReceivedCaplenCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.PacketStatistics#getReceivedPacketCount()
	 */
	@Override
	public long getReceivedPacketCount() {
		return stats.getReceivedPacketCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.PacketStatistics#getReceivedWirelenCount()
	 */
	@Override
	public long getReceivedWirelenCount() {
		return stats.getReceivedWirelenCount();
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#getTimeoutQueueSize()
	 */
	@Override
	public int getTimeoutQueueSize() {
		return ipfConfig.getTimeoutQueueSize();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#getTimeSource()
	 */
	@Override
	public TimestampSource getTimeSource() {
		return ipfConfig.getTimeSource();
	}

	/**
	 * Gets any uncaught exceptions.
	 *
	 * @return the uncaught exception
	 */
	public Optional<Throwable> getUncaughtException() {
		return Optional.ofNullable(preProcessor.getUncaughtException());
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#isIpfAttachComplete()
	 */
	@Override
	public boolean isIpfAttachComplete() {
		return ipfConfig.isIpfAttachComplete();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#isIpfAttachIncomplete()
	 */
	@Override
	public boolean isIpfAttachIncomplete() {
		return ipfConfig.isIpfAttachIncomplete();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#isIpfEnabled()
	 */
	@Override
	public boolean isIpfEnabled() {
		return ipfConfig.isIpfEnabled();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#isIpfPassFragments()
	 */
	@Override
	public boolean isIpfPassFragments() {
		return ipfConfig.isIpfPassFragments();
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#isIpfPassthrough()
	 */
	@Override
	public boolean isIpfPassthrough() {
		return ipfConfig.isIpfPassthrough();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#isIpfReassemblyEnabled()
	 */
	@Override
	public boolean isIpfReassemblyEnabled() {
		return ipfConfig.isIpfReassemblyEnabled();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#isIpfSendComplete()
	 */
	@Override
	public boolean isIpfSendComplete() {
		return ipfConfig.isIpfSendComplete();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#isIpfSendIncomplete()
	 */
	@Override
	public boolean isIpfSendIncomplete() {
		return ipfConfig.isIpfSendIncomplete();
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#isIpfTimeoutOnLast()
	 */
	@Override
	public boolean isIpfTimeoutOnLast() {
		return ipfConfig.isIpfTimeoutOnLast();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfConfig#isIpfTrackingEnabled()
	 */
	@Override
	public boolean isIpfTrackingEnabled() {
		return ipfConfig.isIpfTrackingEnabled();
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
		return postProcessorCommon.loopPacket(count, handler, user);
	}

	/**
	 * Sets the descriptor type.
	 *
	 * @param type the type
	 * @return the pcap pro
	 */
	public PcapPro setDescriptorType(PacketDescriptorType type) {
		checkIpfIsNotActive();

		ipfConfig.descriptorType = type;
		ipfConfig.dissector = PacketDissector.dissector(type);

		var disp = new PacketDispatcherJava(
				ipfConfig);
		disp.setPcapDispatcher(preProcessor);

		this.postProcessorCommon = disp;
		this.stats = postProcessorCommon.getPacketStatistics();

		return this;
	}

	/**
	 * Sets the frame number.
	 *
	 * @param frameNumberAssigner the frame number assigner
	 * @return the pcap pro
	 */
	public PcapPro setFrameNumber(FrameNumber frameNumberAssigner) {
		checkIpfIsNotActive();

		ipfConfig.frameNo = frameNumberAssigner;

		return this;
	}

	/**
	 * Sets the frame starting number.
	 *
	 * @param startingNo the starting no
	 * @return the pcap pro
	 */
	public PcapPro setFrameStartingNumber(long startingNo) {
		checkIpfIsNotActive();

		return setFrameNumber(FrameNumber.starting(startingNo));
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setIpfBufferSize(long,
	 *      com.slytechs.protocol.runtime.util.MemoryUnit)
	 */
	@Override
	public PcapPro setIpfBufferSize(long size, MemoryUnit unit) {
		checkIpfIsNotActive();

		ipfConfig.setIpfBufferSize(size, unit);

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setIpfMaxDgramSize(long,
	 *      com.slytechs.protocol.runtime.util.MemoryUnit)
	 */
	@Override
	public PcapPro setIpfMaxDgramSize(long size, MemoryUnit unit) {
		checkIpfIsNotActive();

		ipfConfig.setIpfMaxDgramSize(size, unit);

		return this;
	}

	/**
	 * Sets the ipf max frag track count.
	 *
	 * @param ipfMaxFragTrackCount the ipf max frag track count
	 * @return the pcap pro
	 */
	public PcapPro setIpfMaxFragmentCount(int ipfMaxFragTrackCount) {
		return setIpfMaxFragmentCount(ipfMaxFragTrackCount, CountUnit.COUNT);
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setIpfMaxFragmentCount(int,
	 *      com.slytechs.protocol.runtime.util.CountUnit)
	 */
	@Override
	public PcapPro setIpfMaxFragmentCount(int ipfMaxFragTrackCount, CountUnit unit) {
		checkIpfIsNotActive();

		ipfConfig.setIpfMaxFragmentCount(ipfMaxFragTrackCount, unit);

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setIpfTableSize(long,
	 *      com.slytechs.protocol.runtime.util.CountUnit)
	 */
	@Override
	public PcapPro setIpfTableSize(long size, CountUnit unit) {
		checkIpfIsNotActive();

		ipfConfig.setIpfTableSize(size, unit);

		return this;
	}

	/**
	 * Sets per entry timeout parameters. Entries can timeout when the last fragment
	 * is seen but not all fragments have arrived or timeout duration has elapsed.
	 * If timeout on last frag is not enabled, then entries are kept alive until
	 * timeout occurs or all fragments arrive, which ever condition occurs first.
	 *
	 * @param timeoutOnLastFrag the timeout on last frag
	 * @param duration          the duration
	 * @param unit              the unit
	 * @return the pcap pro
	 */
	public PcapPro setIpfTimeout(boolean timeoutOnLastFrag, long duration, TimeUnit unit) {
		checkIpfIsNotActive();

		throw new UnsupportedOperationException();
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setIpfTimeout(long,
	 *      java.util.concurrent.TimeUnit)
	 */
	@Override
	public PcapPro setIpfTimeout(long timeout, TimeUnit unit) {
		checkIpfIsNotActive();

		ipfConfig.setIpfTimeout(timeout, unit);

		return this;
	}

	/**
	 * Sets the ipf timeout milli.
	 *
	 * @param timeoutMilli the timeout milli
	 * @return the pcap pro
	 */
	public PcapPro setIpfTimeoutMilli(long timeoutMilli) {
		checkIpfIsNotActive();

		return setIpfTimeout(timeoutMilli, TimeUnit.MILLISECONDS);
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setIpfTimeoutOnLast(boolean)
	 */
	@Override
	public PcapPro setIpfTimeoutOnLast(boolean lastOrTimeout) {
		checkIpfIsNotActive();

		ipfConfig.setIpfTimeoutOnLast(lastOrTimeout);

		return this;
	}

	/**
	 * Sets the packet formatter.
	 *
	 * @param formatter the formatter
	 * @return the pcap pro
	 */
	public PcapPro setPacketFormatter(PacketFormat formatter) {
		ipfConfig.formatter = formatter;

		return this;
	}

	/**
	 * Sets the port number.
	 *
	 * @param portNo the port no
	 * @return the pcap pro
	 */
	public PcapPro setPortNumber(int portNo) {
		checkIpfIsNotActive();

		ipfConfig.portNo = portNo;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setTimeoutQueueSize(int)
	 */
	@Override
	public PcapPro setTimeoutQueueSize(int size) {
		checkIpfIsNotActive();

		ipfConfig.setTimeoutQueueSize(size);

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
		checkIpfIsNotActive();

		ipfConfig.timestampUnit = unit;

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
		checkIpfIsNotActive();

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
		checkIpfIsNotActive();

		super.setUncaughtExceptionHandler(exceptionHandler);

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#useIpfPacketTimesource()
	 */
	@Override
	public PcapPro useIpfPacketTimesource() {
		checkIpfIsNotActive();

		ipfConfig.useIpfPacketTimesource();

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#useIpfSystemTimesource()
	 */
	@Override
	public PcapPro useIpfSystemTimesource() {
		checkIpfIsNotActive();

		ipfConfig.useIpfSystemTimesource();

		return this;
	}

}
