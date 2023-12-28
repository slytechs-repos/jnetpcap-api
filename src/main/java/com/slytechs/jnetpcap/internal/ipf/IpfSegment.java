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
package com.slytechs.jnetpcap.internal.ipf;

import com.slytechs.protocol.runtime.util.Detail;
import com.slytechs.protocol.runtime.util.IntSegment;

/**
 * The Class IpfSegment.
 */
class IpfSegment implements Comparable<IpfSegment>, IntSegment {

	/** The offset. */
	int offset;
	
	/** The length. */
	int length;
	
	/** The overlay. */
	int overlay;
	
	/** The timestamp. */
	long timestamp;
	
	/** The frame no. */
	long frameNo;

	/**
	 * Compare to.
	 *
	 * @param o the o
	 * @return the int
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(IpfSegment o) {
		return this.offset - o.offset;
	}

	/**
	 * @see com.slytechs.protocol.runtime.util.IntSegment#start()
	 */
	@Override
	public int start() {
		return offset;
	}

	/**
	 * @see com.slytechs.protocol.runtime.util.IntSegment#end()
	 */
	@Override
	public int end() {
		return offset + length - 1;
	}

	/**
	 * @see com.slytechs.protocol.runtime.util.IntSegment#endExclusive()
	 */
	@Override
	public int endExclusive() {
		return offset + length;
	}

	/**
	 * @see com.slytechs.protocol.runtime.util.IntSegment#length()
	 */
	@Override
	public int length() {
		return length();
	}

	/**
	 * Reset.
	 */
	public void reset() {
		offset = length = overlay = 0;
		frameNo = -1;
	}

	/**
	 * To string.
	 *
	 * @return the string
	 * @see java.lang. Object#toString()
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
		if (detail == Detail.LOW)
			return "%d-%d".formatted(offset, (offset + length - 1));

		else if (detail == Detail.MEDIUM)
			return "%4d-%4d".formatted(offset, (offset + length - 1));

		else
			return "%4d-%4d (%4d bytes)".formatted(offset, (offset + length - 1), length);

	}

	/**
	 * Calc hole size.
	 *
	 * @param tracks the tracks
	 * @param limit  the limit
	 * @return the int
	 */
	public static int calcHoleSize(IpfSegment[] tracks, int limit) {
		return IntSegment.disjoint(tracks, 0, limit);
	}

	/**
	 * Recalc overlaps.
	 *
	 * @param tracking   the tracking
	 * @param trackCount the track count
	 * @return the int
	 */
	public static int recalcOverlaps(IpfSegment[] tracking, int trackCount) {
		return IntSegment.intersection(tracking, 0, trackCount, (t0, t1, v) -> t1.overlay += v);
	}

}