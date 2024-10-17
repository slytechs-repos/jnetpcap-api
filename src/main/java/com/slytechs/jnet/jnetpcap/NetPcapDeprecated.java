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
import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.foreign.MemorySegment;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapActivatedException;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapIf;
import org.jnetpcap.constant.PcapCode;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapTStampPrecision;
import org.jnetpcap.internal.DelegatePcap;
import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.internal.StandardPcapDispatcher;

import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacket;
import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacketConsumer;
import com.slytechs.jnet.jnetpcap.internal.CaptureStatisticsImpl;
import com.slytechs.jnet.jnetpcap.internal.PacketReceiverConfig;
import com.slytechs.jnet.jnetruntime.pipeline.Pipeline;
import com.slytechs.jnet.jnetruntime.time.TimeSource;
import com.slytechs.jnet.jnetruntime.time.TimestampUnit;
import com.slytechs.jnet.jnetruntime.util.MemoryUnit;
import com.slytechs.jnet.jnetruntime.util.Registration;
import com.slytechs.jnet.jnetruntime.util.RuntimeMultipleExceptions;
import com.slytechs.jnet.protocol.Frame.FrameNumber;
import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.descriptor.PacketDissector;
import com.slytechs.jnet.protocol.meta.PacketFormat;

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
 * reassembly are both enabled. Further more, IPF reassembly can be configured
 * to attach IPF reassembled buffer to the last IP fragment and/or inserted as a
 * new IP data-gram into the dispatcher's packet stream. This way the user
 * packet handler will receive fully reassembled IP datagrams as packets. The
 * default is to not forward individual IP fragments, but deliver the fully
 * reassembled IP data-gram as a new packet, containing all of the IP fragment
 * data combined.
 * </p>
 * 
 * @author Mark Bednarczyk
 */
public final class NetPcapDeprecated extends DelegatePcap<NetPcapDeprecated> implements CaptureStatistics {

	/**
	 * A factory for creating Pcap::create handles.
	 *
	 * @param <T> the generic type
	 */
	public interface CreatePcapFactory<T> {

		/**
		 * New instance.
		 *
		 * @param device the device
		 * @return the pcap
		 * @throws PcapException the pcap exception
		 */
		Pcap newInstance(T device) throws PcapException;
	}

	/**
	 * Context structure for the NetPcap class and its numerous processors.
	 *
	 * @author Mark Bednarczyk
	 */
	public final static class NetPcapContext {

		/** The time source. */
		private TimeSource timeSource = TimeSource.ofRebased();

		/** The pcap type. */
		public final PcapType pcapType;

		/**
		 * Instantiates a new pcap pro context.
		 *
		 * @param pcapType the pcap type.
		 */
		NetPcapContext(PcapType pcapType) {
			this.pcapType = pcapType;
		}

		/**
		 * Gets the time source.
		 *
		 * @return the timeSource
		 */
		public TimeSource getTimeSource() {
			return timeSource;
		}

		/**
		 * Sets the time source.
		 *
		 * @param timeSource the timeSource to set
		 * @return the pcap pro context
		 */
		public NetPcapContext setTimeSource(TimeSource timeSource) {
			this.timeSource = timeSource;

			return this;
		}
	}

	/**
	 * A factory for creating Pcap::openDead handles.
	 */
	public interface OpenDeadPcapFactory {

		/**
		 * New instance.
		 *
		 * @param linktype the linktype
		 * @param snaplen  the snaplen
		 * @return the pcap
		 * @throws PcapException the pcap exception
		 */
		Pcap newInstance(PcapDlt linktype, int snaplen) throws PcapException;
	}

	/**
	 * A factory for creating Pcap::openDeadWithTstampPrecision handles.
	 */
	public interface OpenDeadTsPcapFactory {

		/**
		 * New instance.
		 *
		 * @param linktype  the linktype
		 * @param snaplen   the snaplen
		 * @param precision the precision
		 * @return the pcap
		 * @throws PcapException the pcap exception
		 */
		Pcap newInstance(PcapDlt linktype, int snaplen, PcapTStampPrecision precision) throws PcapException;
	}

	/**
	 * A factory for creating Pcap::openLive handles.
	 *
	 * @param <T> the generic device type
	 */
	public interface OpenLivePcapFactory<T> {

		/**
		 * New instance.
		 *
		 * @param device  the device
		 * @param snaplen the snaplen
		 * @param promisc the promisc
		 * @param timeout the timeout
		 * @param unit    the unit
		 * @return the pcap
		 * @throws PcapException the pcap exception
		 */
		Pcap newInstance(T device, int snaplen, boolean promisc, long timeout, TimeUnit unit) throws PcapException;
	}

	/**
	 * A factory for creating Pcap::openOffline handles.
	 *
	 * @param <T> the generic type
	 */
	public interface OpenOfflinePcapFactory<T> {

		/**
		 * New instance.
		 *
		 * @param file the file
		 * @return the pcap
		 * @throws PcapException the pcap exception
		 */
		Pcap newInstance(T file) throws PcapException;
	}

	/**
	 * Create a live capture handle using a pcap factory.
	 * 
	 * {@code create} is used to create a packet capture handle to look at packets
	 * on the network. source is a string that specifies the network device to open;
	 * on Linux systems with 2.2 or later kernels, a source argument of "any" or
	 * NULL can be used to capture packets from all interfaces. The returned handle
	 * must be activated with pcap_activate() before pack' ets can be captured with
	 * it; options for the capture, such as promiscu' ous mode, can be set on the
	 * handle before activating it.
	 *
	 * @param factory the factory
	 * @param device  pcap network interface that specifies the network device to
	 *                open.
	 * @return a new pcap object that needs to be activated using
	 *         {@link #activate()} call
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public static NetPcapDeprecated create(CreatePcapFactory<PcapIf> factory, PcapIf device) throws PcapException {
		return new NetPcapDeprecated(factory.newInstance(device), PcapType.LIVE_CAPTURE);
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
	 * @param factory the factory
	 * @param device  a string that specifies the network device to open; on Linux
	 *                systems with 2.2 or later kernels, a source argument of "any"
	 *                or NULL can be used to capture packets from all interfaces.
	 * @return a new pcap object that needs to be activated using
	 *         {@link #activate()} call
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public static NetPcapDeprecated create(CreatePcapFactory<String> factory, String device) throws PcapException {
		return new NetPcapDeprecated(factory.newInstance(device), PcapType.LIVE_CAPTURE);
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
	 * @param device pcap network interface that specifies the network device to
	 *               open.
	 * @return a new pcap object that needs to be activated using
	 *         {@link #activate()} call
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public static NetPcapDeprecated create(PcapIf device) throws PcapException {
		return create(Pcap::create, device);
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
	public static NetPcapDeprecated create(String device) throws PcapException {
		return create(Pcap::create, device);
	}

	/**
	 * Open dead.
	 *
	 * @param factory  the factory
	 * @param linktype the linktype
	 * @param snaplen  the snaplen
	 * @return the net pcap
	 * @throws PcapException the pcap exception
	 */
	public static NetPcapDeprecated openDead(OpenDeadPcapFactory factory, PcapDlt linktype, int snaplen) throws PcapException {
		return new NetPcapDeprecated(factory.newInstance(linktype, snaplen), PcapType.DEAD_HANDLE);
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
	public static NetPcapDeprecated openDead(PcapDlt linktype, int snaplen) throws PcapException {
		return openDead(Pcap::openDead, linktype, snaplen);
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
	 * {@link PcapDumper#dump(MemorySegment, MemorySegment)}, and
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
	 * @param factory   the delegate pcap factory
	 * @param linktype  specifies the link-layer type for the pcap handle
	 * @param snaplen   specifies the snapshot length for the pcap handle
	 * @param precision the requested timestamp precision
	 * @return A dead pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 1.5.1
	 */
	public static NetPcapDeprecated openDeadWithTstampPrecision(OpenDeadTsPcapFactory factory, PcapDlt linktype, int snaplen,
			PcapTStampPrecision precision) throws PcapException {
		return new NetPcapDeprecated(factory.newInstance(linktype, snaplen, precision), PcapType.DEAD_HANDLE);
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
	 * {@link PcapDumper#dump(MemorySegment, MemorySegment)}, and
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
	public static NetPcapDeprecated openDeadWithTstampPrecision(PcapDlt linktype, int snaplen, PcapTStampPrecision precision)
			throws PcapException {
		return openDeadWithTstampPrecision(Pcap::openDeadWithTstampPrecision, linktype, snaplen, precision);
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
	 * @param factory the delegate pcap factory
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
	public static NetPcapDeprecated openLive(OpenLivePcapFactory<PcapIf> factory, PcapIf device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit) throws PcapException {

		return new NetPcapDeprecated(factory.newInstance(device, snaplen, promisc, timeout, unit), PcapType.LIVE_CAPTURE);
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
	 * @param factory the delegate pcap factory
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
	public static NetPcapDeprecated openLive(OpenLivePcapFactory<String> factory, String device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit) throws PcapException {

		return new NetPcapDeprecated(factory.newInstance(device, snaplen, promisc, timeout, unit), PcapType.LIVE_CAPTURE);
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
	public static NetPcapDeprecated openLive(PcapIf device, int snaplen, boolean promisc, long timeout, TimeUnit unit)
			throws PcapException {

		return openLive(Pcap::openLive, device, snaplen, promisc, timeout, unit);
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
	public static NetPcapDeprecated openLive(String device, int snaplen, boolean promisc, long timeout, TimeUnit unit)
			throws PcapException {

		return new NetPcapDeprecated(Pcap.openLive(device, snaplen, promisc, timeout, unit), PcapType.LIVE_CAPTURE);
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
	public static NetPcapDeprecated openOffline(File file) throws PcapException {
		return openOffline(Pcap::openOffline, file);
	}

	/**
	 * Open a saved capture file for reading.
	 * 
	 * <p>
	 * pcap_open_offline() and pcap_open_offline_with_tstamp_precision() are called
	 * to open a ``savefile'' for reading.
	 * </p>
	 *
	 * @param factory the delegate pcap factory
	 * @param file    the offline capture file
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.4
	 */
	public static NetPcapDeprecated openOffline(OpenOfflinePcapFactory<File> factory, File file) throws PcapException {
		return new NetPcapDeprecated(factory.newInstance(file), PcapType.OFFLINE_READER);
	}

	/**
	 * Open a saved capture file for reading.
	 * 
	 * <p>
	 * pcap_open_offline() and pcap_open_offline_with_tstamp_precision() are called
	 * to open a ``savefile'' for reading.
	 * </p>
	 *
	 * @param factory the factory
	 * @param fname   specifies the name of the file to open. The file can have the
	 *                pcap file format as described in pcap-savefile(5), which is
	 *                the file format used by, among other programs, tcpdump(1) and
	 *                tcpslice(1), or can have the pcapng file format, although not
	 *                all pcapng files can be read
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.4
	 */
	public static NetPcapDeprecated openOffline(OpenOfflinePcapFactory<String> factory, String fname) throws PcapException {
		return new NetPcapDeprecated(factory.newInstance(fname), PcapType.OFFLINE_READER);
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
	public static NetPcapDeprecated openOffline(String fname) throws PcapException {
		return openOffline(Pcap::openOffline, fname);
	}

	/** The ipf config. */
	private final PacketReceiverConfig config = new PacketReceiverConfig();

	/** The stats. */
	private CaptureStatistics stats = new CaptureStatisticsImpl();

	/** The context. */
	private final NetPcapContext context;

	/** The is active. */
	private boolean isActive;

	/** The close actions. */
	private final List<Runnable> closeActions = new LinkedList<>();

	/** The pcap pipeline. */
	private final PcapPipeline pcapPipeline;

	/** The proto pipeline. */
	private final ProtocolPipeline protoPipeline;

	/** The dispatcher L 0. */
	private final PcapDispatcher dispatcherL0;

	/**
	 * Instantiates a new pcap-pro native handle.
	 * 
	 * <pre>
	 * + NetPcap -> Pcap
	 *   + NetPipeline::pipelineL0
	 *     + NetGroup(RX_PCAP_RAW)
	 *       - PcapDispatcherAdapter::RX_PCAP_RAW(PcapDispatcher::stdPcapDispatcher)
	 *       - PacketRepeater
	 *     + NetGroup(RX_PACKET)
	 *       - PacketDissectorAdapter
	 *     + NetGroup(RX_IPF)
	 *       - IpfReassembler
	 * </pre>
	 *
	 * @param pcap     the pcap
	 * @param pcapType the pcap handle type such as LIVE, OFFLINE or DEAD depending
	 *                 how the pcap-pro handle was opened
	 */
	NetPcapDeprecated(Pcap pcap, PcapType pcapType) {
		super(pcap);
		config.abi = Objects.requireNonNull(getPcapHeaderABI(), "abi");
		config.portName = getName();

		this.dispatcherL0 = new StandardPcapDispatcher(getPcapHandle(), getPcapHeaderABI(), this::breakloop);
		this.pcapPipeline = new PcapPipeline(0);
		this.protoPipeline = this.pcapPipeline.installPipeline(ProtocolPipeline::new);

		this.context = new NetPcapContext(Objects.requireNonNull(pcapType, "pcapType"));

		this.pcapPipeline.context()
				.property(getPcapHandle());

		setDescriptorType(PacketDescriptorType.TYPE2);
		enablePacketFormatter(true);
	}

	/**
	 * Activate the pcap-pro handle and all its resources. If the underlying basic
	 * pcap handle also requires activation, it will also be activated. The pcap-pro
	 * activation will allocated any required related resources such as packet
	 * processors, allocate requested memory buffers and configure pro filters and
	 * packet buffer dissectors.
	 * 
	 * <p>
	 * It is always required to call this {@code activate()} method on a pcap-pro
	 * handle, even if the underlying pcap handle does not require it such as for
	 * dead or offline handles.
	 * </p>
	 *
	 * @throws PcapActivatedException thrown if pcap-pro handle has already been
	 *                                activated, however underlying base pcap handle
	 *                                even for dead, openLive or already otherwise
	 *                                uneccessary activations, are not thrown, as
	 *                                per this pcap-pro extension of this method
	 * @throws PcapException          any pcap exceptions during activation process
	 * @see org.jnetpcap.Pcap1_0#activate()
	 */
	@Override
	public void activate() throws PcapActivatedException, PcapException {
		if (isActive)
			throw new PcapActivatedException(PcapCode.PCAP_ERROR_ACTIVATED, "pcap-pro handle already active");

		activatePipeline();
	}

	/**
	 * Activate pipeline.
	 */
	private void activatePipeline() {
		pipeline().close();
	}

	/**
	 * Check if already active.
	 *
	 * @throws IllegalStateException thrown if handle is not active
	 */
	private void checkIfActiveOrElseThrow() throws IllegalStateException {
		if (!isActive)
			throw new IllegalStateException("inactive - must use Pcap.activate()");
	}

	/**
	 * Check if inactive.
	 *
	 * @throws IllegalStateException the illegal state exception
	 */
	private void checkIfInactiveOrElseThrow() throws IllegalStateException {
		if (isActive)
			throw new IllegalStateException("handle already active");
	}

	/**
	 * Close.
	 *
	 * @see org.jnetpcap.Pcap0_4#close()
	 */
	@Override
	public void close() {
		super.close();

		var exceptions = new LinkedList<RuntimeException>();
		for (Runnable closeAction : closeActions) {
			try {
				closeAction.run();
			} catch (RuntimeException e) {
				exceptions.add(e);
			}
		}
		if (!exceptions.isEmpty())
			throw new RuntimeMultipleExceptions("caught '%s' handle close actions errors"
					.formatted(getName()), exceptions);
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
	public <U> int dispatch(int count, OfPacket<U> handler, U user) {
		checkIfActiveOrElseThrow();

		try (Registration reg = protoPipeline.registerOutput(handler.wrapUser(user))) {
			return dispatcherL0.invokeDispatchNativeCallback(count, pcapPipeline, MemorySegment.NULL);
		}
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
	 * Install factory.
	 *
	 * @param b the b
	 * @return the t
	 */
	public NetPcapDeprecated enableIpf(boolean b) {
		if (b == false)
			return this;

		Pipeline<?, ?> pipeline = pipeline();
		pipeline.install(IpfReassembler::new);

		return this;
	}

	/**
	 * Enable ipf if.
	 *
	 * @param b the b
	 * @return the pcap pro
	 */
	public NetPcapDeprecated enableIpf(BooleanSupplier b) {
		return enableIpf(b.getAsBoolean());
	}

	/**
	 * Enable "pretty print" packet formatter.
	 *
	 * @param b if true enable formatting, otherwise disable formatting and default
	 *          to builtin "terse" packet format
	 * @return this pcap pro instance
	 */
	public NetPcapDeprecated enablePacketFormatter(boolean b) {

		if (b)
			setPacketFormatter(new PacketFormat());
		else
			setPacketFormatter(null);

		return this;
	}

	/**
	 * Gets the context.
	 *
	 * @return the context
	 */
	public NetPcapContext getContext() {
		return context;
	}

	/**
	 * Gets the dropped caplen count.
	 *
	 * @return the dropped caplen count
	 * @see com.slytechs.jnet.jnetpcap.CaptureStatistics#getDroppedCaplenCount()
	 */
	@Override
	public long getDroppedCaplenCount() {
		return stats.getDroppedCaplenCount();
	}

	/**
	 * Gets the dropped packet count.
	 *
	 * @return the dropped packet count
	 * @see com.slytechs.jnet.jnetpcap.CaptureStatistics#getDroppedPacketCount()
	 */
	@Override
	public long getDroppedPacketCount() {
		return stats.getDroppedPacketCount();
	}

	/**
	 * Gets the dropped wirelen count.
	 *
	 * @return the dropped wirelen count
	 * @see com.slytechs.jnet.jnetpcap.CaptureStatistics#getDroppedWirelenCount()
	 */
	@Override
	public long getDroppedWirelenCount() {
		return stats.getDroppedWirelenCount();
	}

	/**
	 * Gets the pcap type.
	 *
	 * @return the pcapType
	 */
	public PcapType getPcapType() {
		return context.pcapType;
	}

	/**
	 * Gets the received caplen count.
	 *
	 * @return the received caplen count
	 * @see com.slytechs.jnet.jnetpcap.CaptureStatistics#getReceivedCaplenCount()
	 */
	@Override
	public long getReceivedCaplenCount() {
		return stats.getReceivedCaplenCount();
	}

	/**
	 * Gets the received packet count.
	 *
	 * @return the received packet count
	 * @see com.slytechs.jnet.jnetpcap.CaptureStatistics#getReceivedPacketCount()
	 */
	@Override
	public long getReceivedPacketCount() {
		return stats.getReceivedPacketCount();
	}

	/**
	 * Gets the received wirelen count.
	 *
	 * @return the received wirelen count
	 * @see com.slytechs.jnet.jnetpcap.CaptureStatistics#getReceivedWirelenCount()
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
		return Optional.ofNullable(dispatcherL0.getUncaughtException());
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
	public <U> int loop(int count, NetPcapHandler.OfPacket<U> handler, U user) {
		checkIfActiveOrElseThrow();

		try (Registration reg = protoPipeline.registerOutput(handler.wrapUser(user))) {
			return dispatcherL0.invokeLoopNativeCallback(count, pcapPipeline, MemorySegment.NULL);
		}
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
		checkIfActiveOrElseThrow();

		return loop(count, (u, p) -> packetConsumer.accept(p), 0);
	}

	/**
	 * Process packets from a live capture or savefile.
	 *
	 * @param packetConsumer the packet consumer
	 * @return returns 0 if count is exhausted or if, when reading from a
	 *         ``savefile'', no more packets are available. It returns
	 *         PCAP_ERROR_BREAK if the loop terminated due to a call to
	 *         pcap_breakloop() before any packets were processed
	 */
	public int loop(OfPacketConsumer packetConsumer) {
		checkIfActiveOrElseThrow();

		return loop(0, (u, p) -> packetConsumer.accept(p), 0);
	}

	/**
	 * On close.
	 *
	 * @param closeAction the close action
	 * @return the registration
	 */
	public Registration onClose(Runnable closeAction) {
		closeActions.add(closeAction);

		return () -> closeActions.remove(closeAction);

	}

	/**
	 * Pipeline.
	 *
	 * @return the processor config
	 */
	public PcapPipeline pipeline() {
		return pcapPipeline;
	}

	/**
	 * Sets the buffer size for a not-yet- activated capture handle.
	 * 
	 * <p>
	 * sets the buffer size that will be used on a capture handle when the handle is
	 * activated to buffer_size, which is in units of bytes
	 * </p>
	 *
	 * @param size the size of the buffer in specified units
	 * @param unit memory units
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 * @since jNetPcap Pro 1.0
	 */
	public NetPcapDeprecated setBufferSize(long size, MemoryUnit unit) throws PcapException {

		super.setBufferSize(unit.toBytesAsInt(size));

		return this;
	}
	
	/**
	 * Protocol stack.
	 *
	 * @return the pcap pipeline
	 */
	public PcapPipeline protocolStack() {
		return pcapPipeline;
	}

	/**
	 * Sets the descriptor type.
	 *
	 * @param type the type
	 * @return the pcap pro
	 */
	public NetPcapDeprecated setDescriptorType(PacketDescriptorType type) {
		config.descriptorType = type;
		config.dissector = PacketDissector.dissector(type);

		return this;
	}

	/**
	 * Sets the frame number.
	 *
	 * @param frameNumberAssigner the frame number assigner
	 * @return the pcap pro
	 */
	public NetPcapDeprecated setFrameNumber(FrameNumber frameNumberAssigner) {
		config.frameNo = frameNumberAssigner;

		return this;
	}

	/**
	 * Sets the frame starting number.
	 *
	 * @param startingNo the starting no
	 * @return the pcap pro
	 */
	public NetPcapDeprecated setFrameStartingNumber(long startingNo) {
		return setFrameNumber(FrameNumber.starting(startingNo));
	}

	/**
	 * Sets the packet formatter.
	 *
	 * @param formatter the formatter
	 * @return the pcap pro
	 */
	public NetPcapDeprecated setPacketFormatter(PacketFormat formatter) {
		config.formatter = formatter;

		return this;
	}

	/**
	 * Sets the port number.
	 *
	 * @param portNo the port no
	 * @return the pcap pro
	 */
	public NetPcapDeprecated setPortNumber(int portNo) {
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
	public NetPcapDeprecated setTimestampUnit(TimestampUnit unit) {
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
	public final NetPcapDeprecated setUncaughtExceptionHandler(Consumer<? super Throwable> exceptionHandler) {
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
	public final NetPcapDeprecated setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		super.setUncaughtExceptionHandler(exceptionHandler);

		return this;
	}

}
