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
package com.slytechs.jnetpcap.pro.internal.ipf;

import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.nio.ByteBuffer;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnetpcap.pro.IpfReassembler;
import com.slytechs.jnetpcap.pro.IpfStatistics;
import com.slytechs.jnetpcap.pro.PcapProHandler.OfPacket;
import com.slytechs.jnetpcap.pro.internal.AbstractPacketDispatcher;
import com.slytechs.jnetpcap.pro.internal.CaptureStatisticsImpl;
import com.slytechs.jnetpcap.pro.internal.PacketDispatcher;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.descriptor.IpfFragDissector;
import com.slytechs.protocol.descriptor.IpfFragment;
import com.slytechs.protocol.descriptor.IpfReassembly;
import com.slytechs.protocol.pack.core.constants.CoreConstants;
import com.slytechs.protocol.runtime.hash.Checksums;

/**
 * The Class JavaIpfDispatcher.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 */
public final class JavaIpfDispatcher extends AbstractPacketDispatcher implements IpfDispatcher {

	public interface DatagramQueue {
		void addDatagram(MemorySegment mseg, int caplen, int wirelen, long expiration, IpfDgramReassembler reassembler);
	}

	private static class ReassembledDatagram {

		private MemorySegment mseg;
		private int caplen;
		private int wirelen;
		private long timestamp;
		private IpfDgramReassembler reassembler;

		ReassembledDatagram(MemorySegment mseg, int caplen, int wirelen, long timestamp,
				IpfDgramReassembler reassembler) {
			this.caplen = caplen;
			this.wirelen = wirelen;
			this.timestamp = timestamp;
			this.mseg = mseg;
			this.reassembler = reassembler;
		}

	}

	/** The ipf dissector. */
	private final IpfFragDissector ipfDissector = new IpfFragDissector();

	/** The ipf desc buffer. */
	private final ByteBuffer fragDescBuffer = ByteBuffer.allocateDirect(CoreConstants.DESC_IPF_FRAG_BYTE_SIZE);
	private final ByteBuffer reassemblyDescBuffer = ByteBuffer.allocateDirect(
			CoreConstants.DESC_IPF_REASSEMBLY_BYTE_SIZE);

	/** The ipf desc. */
	private final IpfFragment fragDesc = new IpfFragment(fragDescBuffer);
	private IpfFragment fragDescIfPresent = null;
	private final IpfReassembly reassemblyDesc = new IpfReassembly(reassemblyDescBuffer);

	/** The ipf table. */
	private final IpfTable ipfTable;

	/** The ipf config. */
	private final IpfReassembler.EffectiveConfig ipfConfig;

	/** The insert queue. */
	private final BlockingQueue<ReassembledDatagram> dgramQueue;

	private final IpfStatistics ipfStats = new IpfStatistics();

	private final PcapHeaderABI abi;

	private final CaptureStatisticsImpl packetStats;

	/**
	 * Instantiates a new java ipf dispatcher.
	 *
	 * @param pcapHandle    the pcap handle
	 * @param breakDispatch the break dispatch
	 * @param config        the config
	 */
	public JavaIpfDispatcher(
			PcapDispatcher pcap,
			PacketDispatcher packet,
			IpfReassembler config) {
		super(packet, pcap);

		if (config.isEnabled() == false)
			throw new IllegalStateException("IPF is disabled");

		this.ipfConfig = config.computeEffectiveConfig();
		this.ipfTable = new IpfTable(config, this::sendMemorySegment);
		this.dgramQueue = new ArrayBlockingQueue<>(config.getTimeoutQueueSize());
		this.abi = pcap.pcapHeaderABI();
		this.packetStats = (CaptureStatisticsImpl) getCaptureStatistics();
	}

	/**
	 * Dispatch ipf.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 */
	protected <U> int dispatchIpf(int count, OfPacket<U> sink, U user) {
		return super.dispatchNative(count, (ignore, pcapHdr, pktData) -> {

			try (var session = MemorySession.openShared()) {

				if (!sinkIpfNative0(pcapHdr, pktData, sink, user, session)) {
					Packet packet = super.processPacket(pcapHdr, pktData, session);
					sink.handlePacket(user, packet);
				}

			}

		}, MemoryAddress.NULL); // We don't pass user object to native dispatcher
	}

	/**
	 * Dispatch packet.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 * @see com.slytechs.jnetpcap.pro.internal.MainPacketDispatcher#dispatchPacket(int,
	 *      com.slytechs.jnetpcap.pro.PcapProHandler.OfPacket, java.lang.Object)
	 */
	@Override
	public <U> int dispatchPacket(int count, OfPacket<U> sink, U user) {
		return this.dispatchIpf(count, sink, user);
	}

	/**
	 * Loop ipf.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 */
	protected <U> int loopIpf(int count, OfPacket<U> sink, U user) {
		return super.loopNative(count, (ignore, pcapHdr, pktData) -> {
			try (var session = MemorySession.openShared()) {

				if (!sinkIpfNative0(pcapHdr, pktData, sink, user, session)) {
					Packet packet = super.processPacket(pcapHdr, pktData, session);
					sink.handlePacket(user, packet);
				}

			}

		}, MemoryAddress.NULL); // We don't pass user object to native dispatcher
	}

	/**
	 * Loop packet.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 * @see com.slytechs.jnetpcap.pro.internal.MainPacketDispatcher#loopPacket(int,
	 *      com.slytechs.jnetpcap.pro.PcapProHandler.OfPacket, java.lang.Object)
	 */
	@Override
	public <U> int loopPacket(int count, OfPacket<U> sink, U user) {
		return this.loopIpf(count, sink, user);
	}

	/**
	 * Process ipf native.
	 *
	 * @param pcapHdr the pcap hdr
	 * @param pktData the pkt data
	 * @param session the session
	 * @return true, if successful
	 */
	protected boolean processIpfNative(MemoryAddress pcapHdr, MemoryAddress pktData, MemorySession session) {

		int caplen = 0, wirelen = 0;
		try {
			/* Pcap header fields */
			caplen = abi.captureLength(pcapHdr);
			wirelen = abi.wireLength(pcapHdr);
			long tvSec = abi.tvSec(pcapHdr);
			long tvUsec = abi.tvUsec(pcapHdr);

			long timestamp = ipfConfig.getTimestampUnit().ofSecond(tvSec, tvUsec);

			MemorySegment mpkt = MemorySegment.ofAddress(pktData, caplen, session);
			ByteBuffer buf = mpkt.asByteBuffer();

			boolean isSuccess = (reassembleFromBuffer(-1, buf, caplen, wirelen, timestamp) != null);
			return isSuccess;

		} catch (Throwable e) {
			packetStats.incDropped(caplen, wirelen, 1);
			onNativeCallbackException(e, caplen, wirelen);
			return false;
		}
	}

	/**
	 * Process ipf packet.
	 *
	 * @param packet the packet
	 * @return true, if successful
	 * @throws IpfReassemblyException
	 */
	protected IpfDgramReassembler processIpfPacket(Packet packet) throws IpfReassemblyException {
		ByteBuffer buf = packet.buffer();
		int caplen = packet.captureLength();
		int wirelen = packet.wireLength();
		long ts = packet.timestamp();
		long frameNo = packet.descriptor().frameNo();

		return reassembleFromBuffer(frameNo, buf, caplen, wirelen, ts);
	}

	/**
	 * Process ipf buffer.
	 *
	 * @param frameNo   the frame no
	 * @param packetBuf the packet buf
	 * @param caplen    the caplen
	 * @param wirelen   the wirelen
	 * @param ts        the ts
	 * @return the ipf fragment
	 */
	protected IpfDgramReassembler reassembleFromBuffer(long frameNo, ByteBuffer packetBuf, int caplen, int wirelen,
			long ts) throws IpfReassemblyException {

		/*
		 * We're single threaded and we reuse the descriptor, so prepare it for another
		 * fragment
		 */

		ipfDissector.reset();
		fragDescIfPresent = null;

		/*
		 * Create an IPF descriptor with specific IPF fragment information, this may be
		 * provided by native libraries as well, that is why everything is passed using
		 * a native memory descriptors.
		 */

		if (ipfDissector.dissectPacket(packetBuf, ts, caplen, wirelen) == 0)
			return null; // Not an IPF packet

		fragDescIfPresent = fragDesc;

		/* Do the Java descriptor bindings so we have a java descriptor */

		ipfDissector.writeDescriptor(fragDescBuffer.clear());
		fragDescBuffer.flip();
		fragDescIfPresent.bind(fragDescBuffer);

		/* Calculate a hashcode on key TUPLE values */
		ByteBuffer key = fragDescIfPresent.keyBuffer();
		long ipfHashcode = Checksums.crc32(key);

		/* Find existing or create a new IPF table entry (in hash table) */
		var reassembler = ipfTable.lookup(fragDescIfPresent, ipfHashcode);
		if (reassembler == null) {
			ipfStats.incTableInsertionFailure(1);

			return null;
		}

		/* Do actual reassembly */
		if (!reassembler.processFragment(frameNo, packetBuf, fragDescIfPresent)) {
			ipfStats.incIpfProcessingFailure(1);

			reassembler.close();

			return null;
		}

		/*
		 * Reassembler sets a 'reassembled' flag when done or timeout on last fragment
		 */

		if (!reassembler.isReassembled())
			return null; // We're not ready to close yet

		IpfDgramReassembler toClose = reassembler;

		/*
		 * Here we send entirely new packet which is built from the reassembled IP
		 * fragment data by the reassembler. The new packet is put on a send queue which
		 * is drained after this IP fragment is dispatched, and if there are any packets
		 * on the queue will be sent as well. We have 2 options, once the reassembler
		 * determines that reassembly is finished. Complete means that reassembler saw
		 * and reassembled all IP fragments and we have a complete IP data-gram to send.
		 * Incomplete means that not all fragments were seen and reassembled, so holes
		 * in data buffer exists. This can occur if the option {@code
		 * IpfConfiguration.setTimeoutOnLast(boolean)} is set.
		 */

		if (reassembler.isComplete() && ipfConfig.dgramsComplete) {

			/* Add completely reassembled buffer/packet to the dispatcher send queue */
			reassembler.addDatagramToQueue(this::sendMemorySegment);
			toClose = null; // Closed after packet processed from queue

		} else if (!reassembler.isComplete() && ipfConfig.dgramsIncomplete) {

			/* Add partially reassembled buffer/packet to the dispatcher send queue */
			reassembler.addDatagramToQueue(this::sendMemorySegment);
			toClose = null; // Closed after packet processed from queue
		}

		/*
		 * Here we attach to each IP fragment a IpfReassembly descriptor which has a
		 * pointer to the IP data-gram reassembled buffer, tracking information and
		 * numerous flags. Unlike, above Dgram packets which were inserted as new
		 * packets, this information is attached to existing IP fragment we just
		 * processed, so all we have to do is add the descriptor.
		 */

		if (ipfConfig.passComplete) {

			reassembler.writeReassemblyDescriptor(reassemblyDescBuffer.clear());
			reassemblyDescBuffer.flip();
			reassemblyDesc.bind(reassemblyDescBuffer);

			fragDescIfPresent.addDescriptor(reassemblyDesc);

		} else if (ipfConfig.passIncomplete) {

			reassembler.writeReassemblyDescriptor(reassemblyDescBuffer.clear());
			reassemblyDescBuffer.flip();
			reassemblyDesc.bind(reassemblyDescBuffer);

			fragDescIfPresent.addDescriptor(reassemblyDesc);
		}

		/*
		 * If toClose is null because we added a reassembled datagram to the dispatch
		 * queue, otherwise, we return the IPF's reassembler so it can be closed
		 * immediately after the IPF is sent directly with attached reassembler data
		 */
		return toClose;
	}

	private void sendMemorySegment(MemorySegment mseg, int caplen, int wirelen, long expiration,
			IpfDgramReassembler reassembler) {
		ReassembledDatagram req = new ReassembledDatagram(mseg, caplen, wirelen, expiration, reassembler);
		dgramQueue.offer(req);
	}

	private <U> void sinkIpDatagram(ReassembledDatagram dgram, OfPacket<U> sink, U user) {
		IpfDgramReassembler reassembler = dgram.reassembler;
		ByteBuffer buf = dgram.mseg.asByteBuffer();

		Packet packet = super.processPacket(buf, dgram.mseg, dgram.caplen, dgram.wirelen, dgram.timestamp);

		reassembler.writeReassemblyDescriptor(reassemblyDescBuffer.clear());
		reassemblyDescBuffer.flip();
		reassemblyDesc.bind(reassemblyDescBuffer);

		packet.descriptor().addDescriptor(reassemblyDesc);

		sink.handlePacket(user, packet);
		packet.unbind();

		/* Close and reset the reassembler for the next IPF data-gram reassembly */
		reassembler.close();
	}

	private <U> boolean sinkIpfNative0(MemoryAddress pcapHdr, MemoryAddress pktData, OfPacket<U> sink, U user,
			MemorySession session) {

		if (ipfConfig.pass) {
			/*
			 * On frag pass through, we create a packet object right away since we are
			 * passing the packet no matter if its IPF or not fragmented. It needs to be
			 * forwarded either way.
			 */

			Packet packet = super.processPacket(pcapHdr, pktData, session);

			/* Assign packet time, if that config option is applied, otherwise ignored */
			ipfConfig.getTimeSource().timestamp(packet.timestamp());

			try {
				IpfDgramReassembler toClose = processIpfPacket(packet);

				packet.descriptor().addDescriptor(fragDescIfPresent);

				/*
				 * OK, we have an IPF fragment so sink as IPF frag (ie. attache IPF tracking or
				 * reassembly).
				 */
				sinkIpfPacket0(packet, sink, user);
				packet.unbind();

				/*
				 * If null, means there is an inserted packet on the packet queue which will
				 * close when done
				 */
				if (toClose != null)
					toClose.close();

				return true;
			} catch (IpfReassemblyException e) {
				e.printStackTrace();
				super.onNativeCallbackException(new RuntimeException(e));

				sink.handlePacket(user, packet);

				packet.unbind();

				return true;
			}

		} else {
			/*
			 * On no-frags pass, we process native memory to gather IPF information in
			 * tables.
			 */
			return processIpfNative(pcapHdr, pktData, session);
		}
	}

	private <U> void sinkIpfPacket0(Packet packet, OfPacket<U> sink, U user) {
		/*
		 * OK, we have an IPF fragment so we need to attach
		 */

		sink.handlePacket(user, packet);
		packet.unbind();

		/*
		 * We check the IP data-gram queue, if any. These data-gram get turned into
		 * packets and dispatched after the last packet was sent to the sink. Packets on
		 * this queue can end up because, we have fully reassembled data-gram, or
		 * because of timeout queue expiration, and manual insertion (future).
		 */
		ReassembledDatagram dgram = null;
		while ((dgram = dgramQueue.poll()) != null) {
			sinkIpDatagram(dgram, sink, user);
		}
	}

}
