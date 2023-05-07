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

import java.util.concurrent.TimeUnit;

import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnetpcap.pro.IpfConfiguration;
import com.slytechs.jnetpcap.pro.internal.PacketDispatcher.PacketDispatcherConfig;
import com.slytechs.protocol.runtime.time.TimestampSource;
import com.slytechs.protocol.runtime.time.TimestampSource.AssignableTimestampSource;
import com.slytechs.protocol.runtime.time.TimestampUnit;
import com.slytechs.protocol.runtime.util.CountUnit;
import com.slytechs.protocol.runtime.util.MemoryUnit;

/**
 * (Private API) IPF configuration implementation.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public class IpfConfig extends PacketDispatcherConfig implements IpfConfiguration {

	// @formatter:off
	
	/* Hashtable and IP reassembler properties */
	private int     maxDgramBytes         = intValue (PROPERTY_IPF_MAX_DGRAM_BYTES,        64,  MemoryUnit.KILOBYTES);
	private int     bufferSize            = intValue (PROPERTY_IPF_BUFFER_SIZE,            16,  MemoryUnit.MEGABYTES);
	private int     tableSize             = intValue (PROPERTY_IPF_TABLE_SIZE,             256, CountUnit.COUNT);
	private int     maxFragmentCount      = intValue (PROPERTY_IPF_MAX_FRAGMENT_COUNT,     16,  CountUnit.COUNT);

	/* Timeout Queue properties */
	private long    timeoutMillis         = longValue(PROPERTY_IPF_TIMEOUT,                2000);
	private boolean timeoutOnLast         = boolValue(PROPERTY_IPF_TIMEOUT_ON_LAST,        false);
	private int     timeoutQueueSize      = intValue (PROPERTY_IPF_TIMEOUT_QUEUE_SIZE,     256, CountUnit.COUNT);

	/* IPF modes */
	private boolean enableIpf             = boolValue(PROPERTY_IPF_ENABLE,                 false);
	private boolean enableIpfTracking     = boolValue(PROPERTY_IPF_ENABLE_TRACKING,        true);
	private boolean enableIpfReassembly   = boolValue(PROPERTY_IPF_ENABLE_REASSEMBLY,      true);

	/* Fragment pass-through and reassembly buffer attachment to fragment properties */
	private boolean fragsPass             = boolValue(PROPERTY_IPF_FRAGS_PASS,             false);
	private boolean fragsPassIncomplete   = boolValue(PROPERTY_IPF_FRAGS_PASS_INCOMPLETE,  true);
	private boolean fragsPassComplete     = boolValue(PROPERTY_IPF_FRAGS_PASS_COMPLETE,    true);
	
	/* Datagram dispatcher send properties - dgrams are inserted into dispatcher stream */
	private boolean dgramsSend            = boolValue(PROPERTY_IPF_DGRAMS_SEND,            true);
	private boolean dgramsSendIncomplete  = boolValue(PROPERTY_IPF_DGRAMS_SEND_INCOMPLETE, false);
	private boolean dgramsSendComplete    = boolValue(PROPERTY_IPF_DGRAMS_SEND_COMPLETE,   true);
	// @formatter:on

	/** Initialized in constructor, either system or packet time */
	private AssignableTimestampSource timeSource;

	/**
	 * Effective or the result of combining of all the main properties and modes
	 */
	public class EffectiveConfig {

		final boolean pass;
		final boolean dgramsComplete;
		final boolean dgramsIncomplete; // On timeout-duration or timeout-last
		final boolean tracking;
		final boolean passComplete;
		final boolean passIncomplete; // On timeout-last
		final AssignableTimestampSource timeSource;

		/**
		 * Compute an effective configuration. Based on all of the configuration
		 * options, compute which modes and options are actu
		 */
		EffectiveConfig() {
			this.pass = fragsPass;
			this.passComplete = enableIpfReassembly && fragsPassComplete;
			this.passIncomplete = enableIpfReassembly && fragsPassIncomplete && timeoutOnLast;

			this.dgramsComplete = dgramsSend && enableIpfReassembly && dgramsSendComplete;
			this.dgramsIncomplete = dgramsSend && enableIpfReassembly && dgramsSendIncomplete;

			this.tracking = enableIpfTracking && fragsPass;
			this.timeSource = IpfConfig.this.timeSource;
		}

		/**
		 * 
		 */
		public AssignableTimestampSource getTimeSource() {
			return timeSource;
		}
		
		public PcapHeaderABI getPcapAbi() {
			return abi;
		}
		
		public TimestampUnit getTimestampUnit() {
			return timestampUnit;
		}
	}

	/**
	 * Instantiates a new ipf config.
	 */
	public IpfConfig() {
		useIpfSystemTimesource();
	}

	/**
	 * Compute effective config.
	 *
	 * @return the effective config
	 */
	EffectiveConfig computeEffectiveConfig() {
		return new EffectiveConfig();
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
		this.fragsPassComplete = ipfAttachComplete;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfAttachIncomplete(boolean)
	 */
	@Override
	public IpfConfiguration enableIpfAttachIncomplete(boolean ipfAttachIncomplete) {
		this.fragsPassIncomplete = ipfAttachIncomplete;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfPassthrough(boolean)
	 */
	@Override
	public IpfConfiguration enableIpfPassthrough(boolean enable) {
		this.dgramsSend = enable;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfPassComplete(boolean)
	 */
	@Override
	public IpfConfiguration enableIpfPassComplete(boolean passDgramsComplete) {
		this.dgramsSendComplete = passDgramsComplete;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfFragments(boolean)
	 */
	@Override
	public IpfConfiguration enableIpfFragments(boolean passFragments) {
		this.fragsPass = passFragments;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableIpfIncomplete(boolean)
	 */
	@Override
	public IpfConfiguration enableIpfIncomplete(boolean passDgramsIncomplete) {
		this.dgramsSendIncomplete = passDgramsIncomplete;
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
	 * @return the timeoutQueueSize
	 */
	@Override
	public int getTimeoutQueueSize() {
		return timeoutQueueSize;
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
		return fragsPassComplete;
	}

	/**
	 * @return the ipfAttachIncomplete
	 */
	@Override
	public boolean isIpfAttachIncomplete() {
		return fragsPassIncomplete;
	}

	/**
	 * @return the enableIpf
	 */
	@Override
	public boolean isIpfEnabled() {
		return enableIpf;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#isIpfTimeoutOnLast()
	 */
	@Override
	public boolean isIpfTimeoutOnLast() {
		return timeoutOnLast;
	}

	@Override
	public boolean isIpfPassthrough() {
		return dgramsSend;
	}

	/**
	 * @return the passDgramsComplete
	 */
	@Override
	public boolean isIpfSendComplete() {
		return dgramsSendComplete;
	}

	/**
	 * @return the passFragments
	 */
	@Override
	public boolean isIpfPassFragments() {
		return fragsPass;
	}

	/**
	 * @return the passDgramsIncomplete
	 */
	@Override
	public boolean isIpfSendIncomplete() {
		return dgramsSendIncomplete;
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
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setIpfTimeoutOnLast(boolean)
	 */
	@Override
	public IpfConfiguration setIpfTimeoutOnLast(boolean lastOrTimeout) {
		this.timeoutOnLast = lastOrTimeout;

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
	 * @param timeoutQueueSize the timeoutQueueSize to set
	 */
	@Override
	public IpfConfiguration setTimeoutQueueSize(int timeoutQueueSize) {
		this.timeoutQueueSize = timeoutQueueSize;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#useIpfPacketTimesource()
	 */
	@Override
	public IpfConfiguration useIpfPacketTimesource() {
		timeSource = TimestampSource.assignable();

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#useIpfSystemTimesource()
	 */
	@Override
	public IpfConfiguration useIpfSystemTimesource() {
		timeSource = TimestampSource.system();

		return this;
	}
}
