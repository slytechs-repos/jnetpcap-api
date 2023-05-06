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

import com.slytechs.protocol.runtime.util.Detail;
import com.slytechs.protocol.runtime.util.IntSegment;

class IpfSegment implements Comparable<IpfSegment>, IntSegment {

	int offset;
	int length;
	int overlay;
	long timestamp;
	long frameNo;

	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(IpfSegment o) {
		return this.offset - o.offset;
	}

	@Override
	public int start() {
		return offset;
	}

	@Override
	public int end() {
		return offset + length - 1;
	}

	@Override
	public int endExclusive() {
		return offset + length;
	}

	@Override
	public int length() {
		return length();
	}

	public void reset() {
		offset = length = overlay = 0;
		frameNo = -1;
	}

	/**
	 * @see java.lang. Object#toString()
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

	public static int calcHoleSize(IpfSegment[] tracks, int limit) {
		return IntSegment.disjoint(tracks, 0, limit);
	}

	public static int recalcOverlaps(IpfSegment[] tracking, int trackCount) {
		return IntSegment.intersection(tracking, 0, trackCount, (t0, t1, v) -> t1.overlay += v);
	}

}