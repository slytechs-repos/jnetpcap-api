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

import com.slytechs.protocol.descriptor.IpfFragDescriptor;
import com.slytechs.protocol.runtime.hash.HashTable.HashEntry;
import com.slytechs.protocol.runtime.time.TimestampSource;
import com.slytechs.protocol.runtime.util.Detail;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public class IpfReassembler {

	private static class Track implements Comparable<Track> {
		int offset;
		int length;
		long timestamp;

		/**
		 * @see java.lang.Comparable#compareTo(java.lang.Object)
		 */
		@Override
		public int compareTo(Track o) {
			return this.offset - o.offset;
		}

		void reset() {

		}

		/**
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return toString(Detail.LOW);
		}

		public String toString(Detail detail) {
			if (detail == Detail.LOW)
				return "%d-%d".formatted(offset, (offset + length - 1));

			else if (detail == Detail.MEDIUM)
				return "%4d-%4d".formatted(offset, (offset + length - 1));

			else
				return "%4d-%4d (%4d bytes)".formatted(offset, (offset + length - 1), length);

		}
	}

	private final int index;
	private final ByteBuffer buffer;

	/**
	 * Time source is tracking the packet timestamp not necessarily the actual
	 * system time. Each packet that arrives updates the time source to its capture
	 * timestamp. This allows packets that are read offline to be analyzed
	 * accurately.
	 */
	private final TimestampSource timeSource;
	private final HashEntry<IpfReassembler> tableEntry;
	private final IpfConfig config;
	private long expiration;
	private long startTimeMilli = 0;

	private int nextTrack = 0;
	private final Track[] tracking;

	private boolean hasFirst;
	private boolean hasLast;

	public IpfReassembler(ByteBuffer buffer, HashEntry<IpfReassembler> tableEntry, IpfConfig config) {
		this.index = tableEntry.index();
		this.buffer = buffer;
		this.tableEntry = tableEntry;
		this.timeSource = config.timeSource;
		this.config = config;
		this.tracking = new Track[config.ipfMaxFragTrackCount];

		IntStream
				.range(0, config.ipfMaxFragTrackCount)
				.forEach(i -> tracking[i] = new Track());
	}

	public boolean processFragment(ByteBuffer packet, IpfFragDescriptor desc) {

		if (startTimeMilli == 0) {

			startTimeMilli = timeSource.timestamp();
			expiration = startTimeMilli + config.timeoutMillis;

		}

		boolean complete = false;

		if (desc.fragOffset() == 0)
			processFirst(packet, desc);

		else if (desc.isLastFrag())
			complete = processLast(packet, desc);

		else
			processMiddle(packet, desc);

		return complete;
	}

	private void processCommon(ByteBuffer packet, IpfFragDescriptor desc) {
		Track track = tracking[nextTrack++];
		track.offset = desc.fragOffset();
		track.length = desc.dataLength();
		track.timestamp = timeSource.timestamp();

	}

	private void processFirst(ByteBuffer packet, IpfFragDescriptor desc) {
		hasFirst = true;
		processCommon(packet, desc);

	}

	private void processMiddle(ByteBuffer packet, IpfFragDescriptor desc) {
		processCommon(packet, desc);

	}

	private boolean processLast(ByteBuffer packet, IpfFragDescriptor desc) {
		hasLast = true;
		processCommon(packet, desc);

		return true;
	}

	public void reset(ByteBuffer key) {
		this.nextTrack = 0;
		this.expiration = timeSource.timestamp() + config.timeoutMillis;
		this.tableEntry.setEmpty(false);
		this.tableEntry.setKey(key);

		startTimeMilli = 0;

		Arrays.stream(tracking).forEach(Track::reset);
	}

	public boolean isExpired() {
		return expiration < timeSource.timestamp();
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

}
