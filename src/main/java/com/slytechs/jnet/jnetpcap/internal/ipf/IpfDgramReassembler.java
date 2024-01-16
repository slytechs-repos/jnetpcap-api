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
package com.slytechs.jnet.jnetpcap.internal.ipf;

import static com.slytechs.jnet.jnetruntime.internal.foreign.ForeignUtils.*;
import static com.slytechs.jnet.protocol.core.constants.CoreConstants.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.slytechs.jnet.jnetpcap.IpfConfiguration;
import com.slytechs.jnet.jnetpcap.IpfReassembler;
import com.slytechs.jnet.jnetpcap.internal.ipf.JavaIpfDispatcher.DatagramQueue;
import com.slytechs.jnet.jnetpcap.internal.ipf.TimeoutQueue.Expirable;
import com.slytechs.jnet.jnetruntime.hash.HashTable.HashEntry;
import com.slytechs.jnet.jnetruntime.time.TimestampSource;
import com.slytechs.jnet.jnetruntime.util.Detail;
import com.slytechs.jnet.protocol.Registration;
import com.slytechs.jnet.protocol.core.constants.CoreConstants;
import com.slytechs.jnet.protocol.descriptor.IpfFragment;
import com.slytechs.jnet.protocol.descriptor.IpfReassemblyLayout;
import com.slytechs.jnet.protocol.descriptor.IpfTrackingLayout;

/**
 * IPF reassembler and/or tracker.
 * 
 * <p>
 * The algorithm is as follows:
 * </p>
 * <ol>
 * <li>The buffer is upto 64K in size (see
 * {@link IpfConfiguration#PROPERTY_IPF_MAX_DGRAM_BYTES}) for the
 * reassembly</li>
 * <li>There are 2 views (slices) of the buffer. One for the capsulating headers
 * found in 1st fragment and the second a IP payload which is fragmented and
 * reassembled in the second view. Ecaps and payload views are aligned so that
 * when data is written to them, the main buffer has continues (connected) data
 * for both. This allows the 1st fragment to be copied whenever the 1st fragment
 * arrives. The main buffer's position and limit properties as set to the entire
 * IP packet and payload.</li>
 * <li>First we add the reassembler to the timeout queue. This ensures that at
 * some point we either timeout on not receiving all of the fragments in the
 * alloted time or if the timeout on last fragment is set, we can timeout when
 * the last fragment is received, even if dgram is incomplete.</li>
 * <li>Since fragments can arrive in any order including some missing, so we
 * assemble payload fragments as they arrive and await the 1st and last
 * fragments.</li>
 * <li>When 1st fragment arrives, we copy fragment data normally but also copy
 * into ecaps headers buffer the beginning of the 1st fragment (L2 and L3
 * headers) and align so it looks connected in the main buffer.</li>
 * <li>As each fragment arrives, we check for holes (missing frags) and if we
 * have the 1st and last fragments with no holes, we know we have complete IP
 * datagram reassembled.</li>
 * <li>If the incompleteOnLast flag is set, we trigger the timeout immediately
 * when we see the last fragment, even if the datagram is incomplete.</li>
 * <li>If the incompleteOnLast flag is not set, the timeout only occurs if the
 * datagram is incomplete and the timeout period expires.</li>
 * <li>When timeout expires, the reassembler is removed from the timeout queue
 * and notifies the dispatcher of the timeout.</li>
 * <li>The dispatcher once notified of a timeout, either attaches the partially
 * reassembled payload to</li>
 * <li>passthrough - enables or disables pass-through of received fragments and
 * reassembled datagram packets</li>
 * <li>passFragments - allows original fragment packets to pass through to
 * client</li>
 * <li>passDgramsIncomplete - pass incomplete datagrams as new packets</li>
 * <li>passDgramsComplete - pass complete datagrams as new packets</li>
 * <li>attachComplete</li>
 * <li>attachIncomplete</li>
 * <li>timeoutOnLast</li>
 * </ol>
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class IpfDgramReassembler implements Expirable {

	/** The Constant ENCAPS_HEADER_MAX_LENGTH. */
	private static final int ENCAPS_HEADER_MAX_LENGTH = 128;

	/** IPF table entry index. */
	private final int index;

	/** The entire storage ecaps + frag data. */
	private final ByteBuffer buffer;
	
	/** The mseg. */
	private final MemorySegment mseg;
	
	/** The session. */
	private Arena session;

	/** The frag data only view of the main storage. */
	private final ByteBuffer ipPayloadView;

	/**
	 * Only the encapsulating header (L2 + L3) view of the main storage, no IP
	 * payload.
	 */
	private final ByteBuffer encapsView;
	/**
	 * Time source is tracking the packet timestamp not necessarily the actual
	 * system time. Each packet that arrives updates the time source to its capture
	 * timestamp. This allows packets that are read offline to be analyzed
	 * accurately.
	 */
	private final TimestampSource timeSource;
	
	/** The table entry. */
	private final HashEntry<IpfDgramReassembler> tableEntry;
	
	/** The config. */
	private final IpfReassembler config;
	
	/** The expiration. */
	private long expiration;

	/** The start time milli. */
	private long startTimeMilli = 0;
	
	/** The reassembled milli. */
	private long reassembledMilli;

	/** The next segment index. */
	private int nextSegmentIndex = 0;
	
	/** The segments. */
	private final IpfSegment[] segments;

	/** The has first. */
	private boolean hasFirst;
	
	/** The has last. */
	private boolean hasLast;
	
	/** The frame no. */
	private long frameNo;

	/** Used to cancel entry on the timeout queue. */
	private Registration timeoutRegistration;

	/** The is ip 4. */
	private boolean isIp4;
	
	/** The is reassembled. */
	private boolean isReassembled;
	
	/** The is complete. */
	private boolean isComplete;
	
	/** The is timeout on last. */
	private boolean isTimeoutOnLast;
	
	/** The observed size. */
	private int observedSize;
	
	/** The reassembled bytes. */
	private int reassembledBytes = 0;
	
	/** The hole bytes. */
	private int holeBytes = 0;
	
	/** The overlap bytes. */
	private int overlapBytes = 0;

	/** The is reassembly enabled. */
	private final boolean isReassemblyEnabled;

	/** The is timeout. */
	private boolean isTimeout;

	/**
	 * Instantiates a new ipf dgram reassembler.
	 *
	 * @param buffer     the entire storage ecaps + frag data
	 * @param tableEntry the table entry
	 * @param config     the config
	 */
	public IpfDgramReassembler(
			ByteBuffer buffer,
			HashEntry<IpfDgramReassembler> tableEntry,
			IpfReassembler config) {

		this.buffer = buffer;
		this.mseg = MemorySegment.ofBuffer(buffer);
		this.ipPayloadView = buffer.slice(ENCAPS_HEADER_MAX_LENGTH, buffer.limit() - ENCAPS_HEADER_MAX_LENGTH);
		this.encapsView = buffer.slice(0, ENCAPS_HEADER_MAX_LENGTH);
		this.index = tableEntry.index();
		this.tableEntry = tableEntry;
		this.timeSource = config.getTimeSource();
		this.config = config;
		this.segments = new IpfSegment[config.getMaxFragmentCount()];

		this.isReassemblyEnabled = config.isReassemblyEnabled();
		this.isTimeoutOnLast = config.isTimeoutOnLast();

		IntStream
				.range(0, config.getMaxFragmentCount())
				.forEach(i -> segments[i] = new IpfSegment());
	}

	/**
	 * Adds the datagram to queue.
	 *
	 * @param queue the queue
	 */
	void addDatagramToQueue(DatagramQueue queue) {

		int caplen = buffer.remaining();
		long timestamp = timeSource.timestamp();

		/*
		 * We create a new memory segment view of the buffer, but most importantly using
		 * the memory session for this reassembly session. When we're done dispatching
		 * packets, we close this session, which prevents any further access to the
		 * underlying memory so we can safely begin reassembly of the next IP data-gram
		 * when this hash table entry comes up again.
		 */
		MemorySegment mseg = MemorySegment.ofBuffer(buffer);
		mseg = mseg.reinterpret(caplen, session, EMPTY_CLEANUP);

		queue.addDatagram(mseg, caplen, caplen, timestamp, this);

	}

	/**
	 * Cancel timeout.
	 */
	public void cancelTimeout() {
		if (timeoutRegistration == null)
			throw new IllegalStateException("timeout not set [#%d]"
					.formatted(index));

		timeoutRegistration.unregister();
		timeoutRegistration = null;
	}

	/**
	 * Close.
	 */
	public void close() {

		this.startTimeMilli = 0;
		this.hasFirst = hasLast = false;
		this.nextSegmentIndex = 0;
		this.isReassembled = false;
		this.expiration = 0;

		Arrays.stream(segments).forEach(IpfSegment::reset);

		/*
		 * Revoke access to buffer's memory. If someone want to retain it, they have to
		 * clone/copy the data before this entry is closed
		 */
		if (session != null) {
			session.close();
			session = null;
		}

		if (timeoutRegistration != null)
			cancelTimeout();

		markHashtableEntryAvailable();

//		System.out.println("close [#%d]".formatted(index));
	}

	/**
	 * Expiration.
	 *
	 * @return the long
	 * @see com.slytechs.jnet.jnetpcap.internal.ipf.TimeoutQueue.Expirable#expiration()
	 */
	@Override
	public long expiration() {
		return this.expiration;
	}

	/**
	 * Finish if complete.
	 */
	private void finishIfComplete() {
		if (!hasLast || holeBytes > 0)
			return;

		cancelTimeout();
		resetHashtableKey();

		this.isReassembled = true;
		this.isComplete = true;
		this.isTimeout = false;

		buffer.position(encapsView.position());
		buffer.limit(ENCAPS_HEADER_MAX_LENGTH + observedSize);

		this.reassembledMilli = timeSource.millis() - startTimeMilli;

		this.overlapBytes = IpfSegment.recalcOverlaps(segments, nextSegmentIndex);
	}

	/**
	 * Finish on timeout.
	 */
	private void finishOnTimeout() {
		this.isReassembled = true;
		this.isComplete = false;
		this.isTimeout = true;

		buffer.position(encapsView.position());
		buffer.limit(ENCAPS_HEADER_MAX_LENGTH + observedSize);

		this.overlapBytes = IpfSegment.recalcOverlaps(segments, nextSegmentIndex);
	}

	/**
	 * Checks if is complete.
	 *
	 * @return true, if is complete
	 */
	public boolean isComplete() {
		return isComplete;
	}

	/**
	 * Checks if is expired.
	 *
	 * @return true, if is expired
	 */
	public boolean isExpired() {
		return expiration < timeSource.timestamp();
	}

	/**
	 * Checks if is reassembled.
	 *
	 * @return the isReassembled
	 */
	public boolean isReassembled() {
		return isReassembled;
	}

	/**
	 * Mark hashtable entry unavailable.
	 */
	private void markHashtableEntryUnavailable() {
		tableEntry.setEmpty(false);
	}

	/**
	 * Mark hashtable entry available.
	 */
	private void markHashtableEntryAvailable() {
		tableEntry.setEmpty(true);
	}

	/**
	 * Open.
	 *
	 * @param key the key
	 */
	public void open(ByteBuffer key) {
		if (session != null)
			throw new IllegalStateException("can not reset, still active");

		this.expiration = timeSource.timestamp() + config.getTimeoutMilli();
		this.tableEntry.setKey(key);
		this.session = Arena.ofShared();

		this.buffer.clear();
		this.observedSize = 0;

		markHashtableEntryUnavailable();

//		System.out.println("open [#%d]".formatted(index));

	}

	/**
	 * Process common.
	 *
	 * @param packet the packet
	 * @param desc   the desc
	 */
	private void processCommon(ByteBuffer packet, IpfFragment desc) {

		/*
		 * If fragment arrives out of order but is the first frag we see, we copy the
		 * L2/L3 headers from it anyway, to have a packet, even with incomplete data.
		 * When 1st frag arrives, it takes priority over middle fragment and will
		 * override this frags headers.
		 */
		if (nextSegmentIndex == 0 && !hasFirst)
			reassembleHeaders(packet, desc);

		IpfSegment ipfSegment = segments[nextSegmentIndex++];
		ipfSegment.offset = desc.fragOffset();
		ipfSegment.length = desc.dataLength();
		ipfSegment.frameNo = frameNo;
		ipfSegment.timestamp = timeSource.timestamp();

		Arrays.sort(segments, 0, nextSegmentIndex);

		this.holeBytes = IpfSegment.calcHoleSize(segments, nextSegmentIndex);

		if (isReassemblyEnabled)
			reassembleFragment(ipfSegment, packet, ipfSegment.offset, ipfSegment.length, desc.dataOffset());
	}

	/**
	 * Process first.
	 *
	 * @param packet the packet
	 * @param desc   the desc
	 * @return true, if successful
	 */
	private boolean processFirst(ByteBuffer packet, IpfFragment desc) {

		/*
		 * First fragment always takes priority, even if it arrives out of order. It may
		 * have options that other fragments do not have
		 */
		if (isReassemblyEnabled && !hasFirst)
			reassembleHeaders(packet, desc);

		hasFirst = true;

		processCommon(packet, desc);
		finishIfComplete();

		return true;
	}

	/**
	 * Process fragment.
	 *
	 * @param frameNo the frame no
	 * @param packet  the packet
	 * @param desc    the desc
	 * @return true, if successful
	 */
	public boolean processFragment(long frameNo, ByteBuffer packet, IpfFragment desc) {
		this.frameNo = frameNo;

		if (!desc.isFrag())
			return false;

		/* No more room for fragments */
		if (nextSegmentIndex == segments.length)
			return false;

		if (startTimeMilli == 0) {
			startTimeMilli = timeSource.timestamp();
			expiration = startTimeMilli + config.getTimeoutMilli();
		}

		this.isIp4 = desc.isIp4();

		boolean ok = false;

		if (desc.fragOffset() == 0) {
			ok = processFirst(packet, desc);

		} else if (desc.isLastFrag()) {
			ok = processLast(packet, desc);

		} else {
			ok = processMiddle(packet, desc);
		}

		return ok;
	}

	/**
	 * Process last.
	 *
	 * @param packet the packet
	 * @param desc   the desc
	 * @return true, if successful
	 */
	private boolean processLast(ByteBuffer packet, IpfFragment desc) {
		hasLast = true;

		processCommon(packet, desc);
		finishIfComplete();

		if (isTimeoutOnLast && !isComplete) {
			cancelTimeout();
			resetHashtableKey();

			finishOnTimeout();
		}

		return true;
	}

	/**
	 * Process middle.
	 *
	 * @param packet the packet
	 * @param desc   the desc
	 * @return true, if successful
	 */
	private boolean processMiddle(ByteBuffer packet, IpfFragment desc) {

		processCommon(packet, desc);
		finishIfComplete();

		return true;
	}

	/**
	 * Reassemble fragment.
	 *
	 * @param ipfSegment the ipf segment
	 * @param packet     the packet
	 * @param fragOffset the frag offset
	 * @param length     the length
	 * @param dataOffset the data offset
	 */
	private void reassembleFragment(IpfSegment ipfSegment, ByteBuffer packet, int fragOffset, int length,
			int dataOffset) {
		ipPayloadView.put(fragOffset, packet, dataOffset, length);

		this.reassembledBytes += length;

		if (observedSize < fragOffset + length)
			this.observedSize = fragOffset + length;
	}

	/**
	 * Reassemble headers.
	 *
	 * @param packet the packet
	 * @param desc   the desc
	 */
	private void reassembleHeaders(ByteBuffer packet, IpfFragment desc) {
		int ecapsLen = desc.headerAndRequiredOptionsLength() + desc.headerOffset();
		int position = ENCAPS_HEADER_MAX_LENGTH - ecapsLen;
		encapsView.clear();

		/* Copy L2 and L3 headers + options to align with fragment data */
		encapsView.put(position, packet, 0, ecapsLen);

		/* Clear IPF related flags/headers in our new reassembled buffer */
		if (desc.isIp4())
			clearIp4Flags(position, desc);
		else
			clearIp6FragmentHeader(position, desc);

		encapsView.position(position);
		buffer.position(position);
	}

	/**
	 * Clear ip 4 flags.
	 *
	 * @param position the position
	 * @param desc     the desc
	 */
	private void clearIp4Flags(int position, IpfFragment desc) {
		/* clear all flags and set fragment offset to 0 */ 
		encapsView.put(position + desc.headerOffset() + CoreConstants.IPv4_FIELD_FLAGS, (byte) 0);
	}

	/**
	 * Clear ip 6 fragment header.
	 *
	 * @param position the position
	 * @param desc     the desc
	 */
	private void clearIp6FragmentHeader(int position, IpfFragment desc) {
	}

	/**
	 * Reset hashtable key.
	 */
	private void resetHashtableKey() {
		this.tableEntry.clearKey();
	}

	/**
	 * Sets the used to cancel entry on the timeout queue.
	 *
	 * @param registration the new used to cancel entry on the timeout queue
	 */
	public void setTimeoutRegistration(Registration registration) {
		timeoutRegistration = registration;
	}

	/**
	 * Called from the timeout queue in the enclosing hash table. We're on the
	 * timeout queue thread as well.
	 *
	 * @param inserter the inserter
	 */
	public void onTimeoutExpired(DatagramQueue inserter) {
		resetHashtableKey();

		finishOnTimeout();

		addDatagramToQueue(inserter);
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return toString(Detail.LOW);
	}

	/**
	 * To string.
	 *
	 * @param detail the detail
	 * @return the string
	 */
	public String toString(Detail detail) {
		String sep = (detail == Detail.LOW) ? "|" : "%n";
		String open = hasFirst ? "[" : "(";
		String close = hasLast ? "]" : ")";

		if (detail == Detail.HIGH) {
			sep = "\n";
			open = close = "";
		}

		return IntStream.range(0, nextSegmentIndex)
				.mapToObj(i -> segments[i].toString(detail))
				.collect(Collectors.joining(sep, open, close));
	}

	/**
	 * Write reassembly descriptor.
	 *
	 * @param desc the desc
	 * @return the int
	 */
	public int writeReassemblyDescriptor(ByteBuffer desc) {

		IpfReassemblyLayout.IP_IS_REASSEMBLED.setBoolean(isReassembled, desc);
		IpfReassemblyLayout.IP_IS_COMPLETE.setBoolean(isComplete, desc);
		IpfReassemblyLayout.IP_IS_TIMEOUT.setBoolean(isTimeout, desc);
		IpfReassemblyLayout.IP_TYPE.setBoolean(isIp4, desc);
		IpfReassemblyLayout.IP_IS_HOLE.setBoolean(holeBytes > 0, desc);
		IpfReassemblyLayout.IP_IS_OVERLAP.setBoolean(overlapBytes > 0, desc);

		IpfReassemblyLayout.HOLE_BYTES.setShort((short) holeBytes, desc);
		IpfReassemblyLayout.OVERLAP_BYTES.setShort((short) overlapBytes, desc);
		IpfReassemblyLayout.REASSEMBLED_BYTES.setShort((short) observedSize, desc);
		IpfReassemblyLayout.REASSEMBLED_MILLI.setShort((short) reassembledMilli, desc);

		int recordCount = nextSegmentIndex;

		IpfReassemblyLayout.TABLE_SIZE.setByte((byte) recordCount, desc);
		for (int i = 0; i < segments.length; i++) {
			IpfSegment track = segments[i];
			IpfReassemblyLayout.FRAG_PKT_INDEX.setLong(track.frameNo, desc, i);
			IpfReassemblyLayout.FRAG_OFFSET.setShort((short) track.offset, desc, i);
			IpfReassemblyLayout.FRAG_LENGTH.setShort((short) track.length, desc, i);
			IpfReassemblyLayout.FRAG_OVERLAY_BYTES.setShort((short) track.overlay, desc, i);
		}

		int len = DESC_IPF_REASSEMBLY_BYTE_MIN_SIZE + (DESC_IPF_REASSEMBLY_RECORD_SIZE * recordCount);

		desc.position(desc.position() + len);

		return len;
	}

	/**
	 * Write tracking descriptor.
	 *
	 * @param desc the desc
	 * @return the int
	 */
	public int writeTrackingDescriptor(ByteBuffer desc) {

		IpfTrackingLayout.IP_IS_REASSEMBLED.setBoolean(true, desc);
		IpfTrackingLayout.IP_IS_COMPLETE.setBoolean(isComplete, desc);
		IpfTrackingLayout.IP_IS_TIMEOUT.setBoolean(isTimeout, desc);
		IpfTrackingLayout.IP_IS_HOLE.setBoolean(holeBytes > 0, desc);
		IpfTrackingLayout.IP_IS_OVERLAP.setBoolean(overlapBytes > 0, desc);

		IpfTrackingLayout.REASSEMBLED_BYTES.setShort((short) reassembledBytes, desc);
		IpfTrackingLayout.HOLE_BYTES.setShort((short) holeBytes, desc);
		IpfTrackingLayout.OVERLAP_BYTES.setShort((short) overlapBytes, desc);
		IpfTrackingLayout.REASSEMBLED_MILLI.setLong(reassembledMilli, desc);

		IpfTrackingLayout.TABLE_SIZE.setByte((byte) nextSegmentIndex, desc);
		for (int i = 0; i < segments.length; i++) {
			IpfSegment track = segments[i];
			IpfTrackingLayout.FRAG_PKT_INDEX.setLong(track.frameNo, desc, i);
			IpfTrackingLayout.FRAG_OFFSET.setShort((short) track.offset, desc, i);
			IpfTrackingLayout.FRAG_LENGTH.setShort((short) track.length, desc, i);
		}

		final int len = 16 + (nextSegmentIndex * 16);
		desc.position(desc.position() + len);

		return len;
	}
}
