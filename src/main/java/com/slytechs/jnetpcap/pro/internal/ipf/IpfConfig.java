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

import java.time.Instant;
import java.util.concurrent.TimeUnit;

import com.slytechs.jnetpcap.pro.internal.PacketDispatcher.PacketDispatcherConfig;
import com.slytechs.protocol.runtime.time.TimestampSource;
import com.slytechs.protocol.runtime.time.TimestampSource.AssignableTimestampSource;
import com.slytechs.protocol.runtime.util.CountUnit;
import com.slytechs.protocol.runtime.util.MemoryUnit;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public class IpfConfig extends PacketDispatcherConfig {

	public static final long DEFAULT_TIMEOUT_MILLI = TimeUnit.SECONDS.toMillis(2);
	public static final int DEFAULT_TABLE_SIZE = CountUnit.KILO.toCountAsInt(16);
	public static final int DEFAULT_IP_MAX_SIZE = MemoryUnit.KILOBYTES.toBytesAsInt(64);
	public static final int DEFAULT_BUFFER_SIZE = DEFAULT_TABLE_SIZE * DEFAULT_IP_MAX_SIZE;

	int ipMaxSize = DEFAULT_IP_MAX_SIZE;
	int bufferSize = DEFAULT_BUFFER_SIZE;
	int tableSize = DEFAULT_TABLE_SIZE;
	long timeoutMillis = DEFAULT_TIMEOUT_MILLI;
	boolean passFragments;
	boolean passIncompleteDatagrams;
	AssignableTimestampSource timeSource;

	public boolean ipfTrackOnly;
	public int ipfMaxFragTrackCount = 16;

	public IpfConfig() {

		useSystemTimesource();
	}

	public IpfConfig setBufferSize(long size, MemoryUnit unit) {
		this.bufferSize = unit.toBytesAsInt(size);
		this.tableSize = bufferSize / ipMaxSize;

		return this;
	}

	public IpfConfig setTableSize(long size, CountUnit unit) {
		this.tableSize = unit.toCountAsInt(size);
		this.bufferSize = tableSize * ipMaxSize;

		return this;
	}

	public IpfConfig setIpMaxSize(long size, MemoryUnit unit) {
		this.ipMaxSize = unit.toBytesAsInt(size);
		this.bufferSize = tableSize * ipMaxSize;

		return this;
	}

	public IpfConfig usePacketTimesource() {
		timeSource = new AssignableTimestampSource() {
			long tsInEpochMilli;

			@Override
			public Instant instant() {
				return Instant.ofEpochMilli(tsInEpochMilli);
			}

			@Override
			public long timestamp() {
				return tsInEpochMilli;
			}

			@Override
			public void timestamp(long packetTimestamp) {
				this.tsInEpochMilli = timestampUnit.toEpochMilli(packetTimestamp);
			}
		};

		return this;
	}

	public IpfConfig useSystemTimesource() {
		timeSource = new AssignableTimestampSource() {

			TimestampSource ts = TimestampSource.system();

			@Override
			public Instant instant() {
				return Instant.ofEpochMilli(timestamp());
			}

			@Override
			public long timestamp() {
				return ts.timestamp();
			}

			@Override
			public void timestamp(long packetTimestamp) {
				// Ignored
			}
		};

		return this;
	}

	public IpfConfig setTimeout(long timeout, TimeUnit unit) {
		this.timeoutMillis = unit.toMillis(timeout);

		return this;
	}
}
