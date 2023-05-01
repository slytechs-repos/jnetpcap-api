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

class IpfTrack implements Comparable<IpfTrack> {

	int offset;
	int length;
	long timestamp;
	long frameNo;

	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(IpfTrack o) {
		return this.offset - o.offset;
	}

	public int start() {
		return offset;
	}

	public int end() {
		return offset + length - 1;
	}

	public int endInclusive() {
		return offset + length;
	}

	public int length() {
		return length();
	}

	public void reset() {

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
}