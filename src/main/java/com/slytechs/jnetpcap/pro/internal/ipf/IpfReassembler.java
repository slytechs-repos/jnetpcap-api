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

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.slytechs.jnetpcap.pro.IpfConfiguration;
import com.slytechs.jnetpcap.pro.internal.ipf.JavaIpfDispatcher.PacketInserter;
import com.slytechs.jnetpcap.pro.internal.ipf.TimeoutQueue.Expirable;
import com.slytechs.protocol.Registration;
import com.slytechs.protocol.descriptor.IpfFragment;
import com.slytechs.protocol.runtime.hash.HashTable.HashEntry;
import com.slytechs.protocol.runtime.time.TimestampSource;
import com.slytechs.protocol.runtime.util.Detail;

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
public class IpfReassembler implements Expirable {

	private static final int ENCAPS_HEADER_MAX_LENGTH = 128;

	/** IPF table entry index */
	private final int index;

	/** The entire storage ecaps + frag data */
	private final ByteBuffer buffer;

	/** The frag data only view of the main storage */
	private final ByteBuffer ipPayloadView;

	/**
	 * Only the encapsulating header (L2 + L3) view of the main storage, no IP
	 * payload
	 */
	private final ByteBuffer encapsView;
	/**
	 * Time source is tracking the packet timestamp not necessarily the actual
	 * system time. Each packet that arrives updates the time source to its capture
	 * timestamp. This allows packets that are read offline to be analyzed
	 * accurately.
	 */
	private final TimestampSource timeSource;
	private final HashEntry<IpfReassembler> tableEntry;
	private final IpfConfiguration config;
	private long expiration;

	private long startTimeMilli = 0;
	private int nextTrack = 0;

	private final IpfTrack[] tracking;
	private boolean hasFirst;
	private boolean hasLast;
	private long frameNo;
	/** Used to cancel entry on the timeout queue */
	private Registration timeoutRegistration;
	private boolean isComplete;

	private final boolean isReassemblyEnabled;

	public IpfReassembler(
			ByteBuffer buffer,
			HashEntry<IpfReassembler> tableEntry,
			IpfConfiguration config) {

		this.buffer = buffer;
		this.ipPayloadView = buffer.slice(ENCAPS_HEADER_MAX_LENGTH, buffer.limit() - ENCAPS_HEADER_MAX_LENGTH);
		this.encapsView = buffer.slice(0, ENCAPS_HEADER_MAX_LENGTH);
		this.index = tableEntry.index();
		this.tableEntry = tableEntry;
		this.timeSource = config.getTimeSource();
		this.config = config;
		this.tracking = new IpfTrack[config.getIpfMaxFragmentCount()];

		this.isReassemblyEnabled = config.isIpfReassemblyEnabled();

		IntStream
				.range(0, config.getIpfMaxFragmentCount())
				.forEach(i -> tracking[i] = new IpfTrack());
	}

	public ByteBuffer buffer() {
		return this.buffer;
	}

	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Long o) {
		return (int) (expiration - o.longValue());
	}

	private void finishIfComplete() {

		/*
		 * If the last segment is reassembled and we have no more holes left, we use
		 * timeout registration, to trigger and do the following:
		 * 
		 * 1) Disengage the timeout queue entry
		 * 
		 * 2) Move the IPF entry from timeout queue to reassembled queue (done in
		 * layered unregister() call)
		 */
		if (hasHole() == false) {
			isComplete = true;
		}
	}

	private boolean hasHole() {
		int holeSize = TrackUtil.calcHoleSize(tracking, nextTrack);

		return holeSize > 0;
	}

	public boolean isComplete() {
		return isComplete;
	}

	public boolean isExpired() {
		return expiration < timeSource.timestamp();
	}

	private void processCommon(ByteBuffer packet, IpfFragment desc) {

		/*
		 * If fragment arrives out of order but is the first frag we see, we copy the
		 * L2/L3 headers from it anyway, to have a packet, even with incomplete data.
		 * When 1st frag arrives, it takes priority over middle fragment and will
		 * override this frags headers.
		 */
		if (nextTrack == 0 && !hasFirst)
			reassembleHeaders(packet, desc);

		IpfTrack ipfTrack = tracking[nextTrack++];
		ipfTrack.offset = desc.fragOffset();
		ipfTrack.length = desc.dataLength();
		ipfTrack.frameNo = frameNo;
		ipfTrack.timestamp = timeSource.timestamp();

		Arrays.sort(tracking, 0, nextTrack);

		if (isReassemblyEnabled)
			reassembleFragment(ipfTrack, packet, ipfTrack.offset, ipfTrack.length, desc.dataOffset());
	}

	private boolean processFirst(ByteBuffer packet, IpfFragment desc) {

		/*
		 * First fragment always takes priority, even if it arrives out of order. It may
		 * have options that other fragments do not have
		 */
		if (isReassemblyEnabled && !hasFirst)
			reassembleHeaders(packet, desc);

		hasFirst = true;

		processCommon(packet, desc);

		return true;
	}

	private void reassembleHeaders(ByteBuffer packet, IpfFragment desc) {
		int ecapsLen = desc.headerAndRequiredOptionsLength();
		int position = ENCAPS_HEADER_MAX_LENGTH - ecapsLen;
		encapsView.clear();

		/* Copy L2 and L3 headers + options to align with fragment data */
		encapsView.put(position, packet, 0, ecapsLen);

		encapsView.position(position);
		buffer.position(position);
	}

	public boolean processFragment(long frameNo, ByteBuffer packet, IpfFragment desc) {
		this.frameNo = frameNo;

		if (!desc.isFrag())
			return false;

		if (startTimeMilli == 0) {
			startTimeMilli = timeSource.timestamp();
			expiration = startTimeMilli + config.getIpfTimeoutMilli();
		}

		boolean complete = false;

		if (desc.fragOffset() == 0) {
			complete = processFirst(packet, desc);

		} else if (desc.isLastFrag()) {
			complete = processLast(packet, desc);

		} else {
			complete = processMiddle(packet, desc);
		}

		return complete;
	}

	private void timeoutOnLast(ByteBuffer packet, IpfFragment desc) {

	}

	/**
	 * Called from the timeout queue in the enclosing hash table. We're on the
	 * timeout queue thread as well.
	 */
	public void timeoutOnDurationExpired(PacketInserter inserter) {

		/*
		 * First, we must reset the key, so any new fragments that come in after the
		 * timeout, won't be matched with this entry and create concurrency issues by
		 * modifying the buffer until we finish inserting/sending the packet.
		 * 
		 * We're on 2 separate threads here.
		 */
		resetHashtableKey();

		int caplen = buffer.remaining();
		inserter.insertNewPacket(buffer, caplen, caplen, expiration, this::onTimedoutPacketInsertionCompletion);
	}

	private void resetHashtableKey() {

	}

	private void onTimedoutPacketInsertionCompletion(boolean success) {
		markHashtableEntryAvailable();
	}

	private void markHashtableEntryAvailable() {
		tableEntry.setEmpty(true);
	}

	private void markHashtableEntryUnavailable() {
		tableEntry.setEmpty(false);
	}

	private boolean processLast(ByteBuffer packet, IpfFragment desc) {
		hasLast = true;
		processCommon(packet, desc);

		return true;
	}

	private boolean processMiddle(ByteBuffer packet, IpfFragment desc) {
		processCommon(packet, desc);

		if (hasLast)
			finishIfComplete();

		return true;
	}

	private void reassembleFragment(IpfTrack ipfTrack, ByteBuffer packet, int fragOffset, int length, int dataOffset) {
		ipPayloadView.put(fragOffset, packet, dataOffset, length);
	}

	public void reset(ByteBuffer key) {
		this.nextTrack = 0;
		this.expiration = timeSource.timestamp() + config.getIpfTimeoutMilli();
		this.tableEntry.setKey(key);

		markHashtableEntryUnavailable();

		startTimeMilli = 0;
		hasFirst = hasLast = false;

		Arrays.stream(tracking).forEach(IpfTrack::reset);
	}

	@Override
	public String toString() {
		return toString(Detail.LOW);
	}

	public String toString(Detail detail) {
		String sep = (detail == Detail.LOW) ? "|" : "%n";
		String open = hasFirst ? "[" : "(";
		String close = hasLast ? "]" : ")";

		if (detail == Detail.HIGH) {
			sep = "\n";
			open = close = "";
		}

		return IntStream.range(0, nextTrack)
				.mapToObj(i -> tracking[i].toString(detail))
				.collect(Collectors.joining(sep, open, close));
	}

	/**
	 * @param registration
	 */
	public void setCancelTimeoutRegistration(Registration registration) {
		timeoutRegistration = registration;
	}
}
