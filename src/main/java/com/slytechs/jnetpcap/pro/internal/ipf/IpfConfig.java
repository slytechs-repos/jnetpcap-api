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

import static com.slytechs.protocol.runtime.util.SystemProperties.*;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

import com.slytechs.jnetpcap.pro.IpfConfiguration;
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
public class IpfConfig extends PacketDispatcherConfig implements IpfConfiguration {

	// @formatter:off
	private int     maxDgramBytes         = intValue (PROPERTY_IPF_MAX_DGRAM_BYTES,        64,  MemoryUnit.KILOBYTES);
	private int     bufferSize            = intValue (PROPERTY_IPF_BUFFER_SIZE,            16, MemoryUnit.MEGABYTES);
	private int     tableSize             = intValue (PROPERTY_IPF_TABLE_SIZE,             256,  CountUnit.COUNT);
	private int     maxFragmentCount      = intValue (PROPERTY_IPF_MAX_FRAGMENT_COUNT,     16,  CountUnit.COUNT);
	private long    timeoutMillis         = longValue(PROPERTY_IPF_TIMEOUT,                2000);
	private boolean enableIpf             = boolValue(PROPERTY_IPF_ENABLE,                 false);
	private boolean enableIpfTracking     = boolValue(PROPERTY_IPF_ENABLE_TRACKING,        true);
	private boolean enableIpfReassembly   = boolValue(PROPERTY_IPF_ENABLE_REASSEMBLY,      true);
	private boolean passthrough           = boolValue(PROPERTY_IPF_PASS,                   true);
	private boolean passFragments         = boolValue(PROPERTY_IPF_PASS_FRAGMENTS,         true);
	private boolean passDgramsIncomplete  = boolValue(PROPERTY_IPF_PASS_DGRAMS_INCOMPLETE, false);
	private boolean passDgramsComplete    = boolValue(PROPERTY_IPF_PASS_DGRAMS_COMPLETE,   false);
	private boolean attachComplete        = boolValue(PROPERTY_IPF_ATTACH_COMPLETE,        true);
	private boolean attachIncomplete      = boolValue(PROPERTY_IPF_ATTACH_INCOMPLETE,      false);
	private boolean incompleteOnLast      = boolValue(PROPERTY_IPF_INCOMPLETE_ON_LAST,     false);
	// @formatter:on

	/** Initialized in constructor, either system or packet time */
	AssignableTimestampSource timeSource;

	public IpfConfig() {
		useIpfSystemTimesource();
	}

	@Override
	public boolean isIpfPassthrough() {
		return passthrough;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpf(boolean)
	 */
	@Override
	public IpfConfiguration enableIpf(boolean enable) {
		this.enableIpf = enable;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfAttachComplete(boolean)
	 */
	@Override
	public IpfConfiguration enableIpfAttachComplete(boolean ipfAttachComplete) {
		this.attachComplete = ipfAttachComplete;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfAttachIncomplete(boolean)
	 */
	@Override
	public IpfConfiguration enableIpfAttachIncomplete(boolean ipfAttachIncomplete) {
		this.attachIncomplete = ipfAttachIncomplete;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfPassthroughComplete(boolean)
	 */
	@Override
	public IpfConfiguration enableIpfPassthroughComplete(boolean passDgramsComplete) {
		this.passDgramsComplete = passDgramsComplete;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfPassthroughFragments(boolean)
	 */
	@Override
	public IpfConfiguration enableIpfPassthroughFragments(boolean passFragments) {
		this.passFragments = passFragments;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfPassthroughIncomplete(boolean)
	 */
	@Override
	public IpfConfiguration enableIpfPassthroughIncomplete(boolean passDgramsIncomplete) {
		this.passDgramsIncomplete = passDgramsIncomplete;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfReassembly(boolean)
	 */
	@Override
	public IpfConfiguration enableIpfReassembly(boolean enable) {
		this.enableIpfReassembly = enable;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfTracking(boolean)
	 */
	@Override
	public IpfConfiguration enableIpfTracking(boolean enable) {
		this.enableIpfTracking = enable;

		return this;
	}

	/**
	 * @return the bufferSize
	 */
	@Override
	public int getIpfBufferSize() {
		return bufferSize;
	}

	/**
	 * @return the ipMaxDgramBytes
	 */
	@Override
	public int getIpfMaxDgramBytes() {
		return maxDgramBytes;
	}

	/**
	 * @return the ipfMaxFragTrackCount
	 */
	@Override
	public int getIpfMaxFragmentCount() {
		return maxFragmentCount;
	}

	/**
	 * @return the tableSize
	 */
	@Override
	public int getIpfTableSize() {
		return tableSize;
	}

	/**
	 * @return the timeoutMillis
	 */
	@Override
	public long getIpfTimeoutMilli() {
		return timeoutMillis;
	}

	/**
	 * @return the timeSource
	 */
	@Override
	public TimestampSource getTimeSource() {
		return timeSource;
	}

	/**
	 * @return the ipfAttachComplete
	 */
	@Override
	public boolean isIpfAttachComplete() {
		return attachComplete;
	}

	/**
	 * @return the ipfAttachIncomplete
	 */
	@Override
	public boolean isIpfAttachIncomplete() {
		return attachIncomplete;
	}

	/**
	 * @return the enableIpf
	 */
	@Override
	public boolean isIpfEnabled() {
		return enableIpf;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#isIpfIncompleteOnLast()
	 */
	@Override
	public boolean isIpfIncompleteOnLast() {
		return incompleteOnLast;
	}

	/**
	 * @return the passDgramsComplete
	 */
	@Override
	public boolean isIpfPassthroughComplete() {
		return passDgramsComplete;
	}

	/**
	 * @return the passDgramsIncomplete
	 */
	@Override
	public boolean isIpfPassthroughIncomplete() {
		return passDgramsIncomplete;
	}

	/**
	 * @return the passFragments
	 */
	@Override
	public boolean isIpfPassthroughFragments() {
		return passFragments;
	}

	/**
	 * @return the enableIpfReassembly
	 */
	@Override
	public boolean isIpfReassemblyEnabled() {
		return enableIpfReassembly;
	}

	/**
	 * @return the enableIpfTracking
	 */
	@Override
	public boolean isIpfTrackingEnabled() {
		return enableIpfTracking;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setIpfBufferSize(long,
	 *      com.slytechs.protocol.runtime.util.MemoryUnit)
	 */
	@Override
	public IpfConfiguration setIpfBufferSize(long size, MemoryUnit unit) {
		this.bufferSize = unit.toBytesAsInt(size);
		this.tableSize = bufferSize / maxDgramBytes;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setIpfIncompleteOnLast(boolean)
	 */
	@Override
	public IpfConfiguration setIpfIncompleteOnLast(boolean lastOrTimeout) {
		this.incompleteOnLast = lastOrTimeout;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setIpfMaxDgramSize(long,
	 *      com.slytechs.protocol.runtime.util.MemoryUnit)
	 */
	@Override
	public IpfConfiguration setIpfMaxDgramSize(long size, MemoryUnit unit) {
		this.maxDgramBytes = unit.toBytesAsInt(size);
		this.bufferSize = tableSize * maxDgramBytes;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setIpfMaxFragmentCount(int)
	 */
	@Override
	public IpfConfiguration setIpfMaxFragmentCount(int ipfMaxFragTrackCount, CountUnit unit) {
		this.maxFragmentCount = ipfMaxFragTrackCount;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setIpfTableSize(long,
	 *      com.slytechs.protocol.runtime.util.CountUnit)
	 */
	@Override
	public IpfConfiguration setIpfTableSize(long size, CountUnit unit) {
		this.tableSize = unit.toCountAsInt(size);
		this.bufferSize = tableSize * maxDgramBytes;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setIpfTimeout(long,
	 *      java.util.concurrent.TimeUnit)
	 */
	@Override
	public IpfConfiguration setIpfTimeout(long timeout, TimeUnit unit) {
		this.timeoutMillis = unit.toMillis(timeout);

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#useIpfPacketTimesource()
	 */
	@Override
	public IpfConfiguration useIpfPacketTimesource() {
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

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#useIpfSystemTimesource()
	 */
	@Override
	public IpfConfiguration useIpfSystemTimesource() {
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

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfPassthrough(boolean)
	 */
	@Override
	public IpfConfiguration enableIpfPassthrough(boolean enable) {
		this.passthrough = enable;

		return this;
	}
}
