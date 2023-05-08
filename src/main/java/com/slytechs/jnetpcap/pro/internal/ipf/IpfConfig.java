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
import com.slytechs.jnetpcap.pro.internal.PacketDispatcherConfig;
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
	private boolean enable             = boolValue(PROPERTY_IPF_ENABLE,                 false);
	private boolean enableTracking     = boolValue(PROPERTY_IPF_ENABLE_TRACKING,        true);
	private boolean enableReassembly   = boolValue(PROPERTY_IPF_ENABLE_REASSEMBLY,      true);

	/* Fragment pass-through and reassembly buffer attachment to fragment properties */
	private boolean fragsPass             = boolValue(PROPERTY_IPF_FRAGS_PASS,             false);
	private boolean fragsPassIncomplete   = boolValue(PROPERTY_IPF_FRAGS_PASS_INCOMPLETE,  true);
	private boolean fragsPassComplete     = boolValue(PROPERTY_IPF_FRAGS_PASS_COMPLETE,    true);
	
	/* Datagram dispatcher send properties - dgrams are inserted into dispatcher stream */
	private boolean dgramSend            = boolValue(PROPERTY_IPF_DGRAMS_SEND,            true);
	private boolean dgramSendIncomplete  = boolValue(PROPERTY_IPF_DGRAMS_SEND_INCOMPLETE, false);
	private boolean dgramSendComplete    = boolValue(PROPERTY_IPF_DGRAMS_SEND_COMPLETE,   true);
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
			this.passComplete = enableReassembly && fragsPassComplete;
			this.passIncomplete = enableReassembly && fragsPassIncomplete && timeoutOnLast;

			this.dgramsComplete = dgramSend && enableReassembly && dgramSendComplete;
			this.dgramsIncomplete = dgramSend && enableReassembly && dgramSendIncomplete;

			this.tracking = enableTracking && fragsPass;
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
		useSystemTimesource();
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
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enable(boolean)
	 */
	@Override
	public IpfConfiguration enable(boolean enable) {
		this.enable = enable;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableAttachComplete(boolean)
	 */
	@Override
	public IpfConfiguration enableAttachComplete(boolean ipfAttachComplete) {
		this.fragsPassComplete = ipfAttachComplete;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableAttachIncomplete(boolean)
	 */
	@Override
	public IpfConfiguration enableAttachIncomplete(boolean ipfAttachIncomplete) {
		this.fragsPassIncomplete = ipfAttachIncomplete;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enablePassthrough(boolean)
	 */
	@Override
	public IpfConfiguration enablePassthrough(boolean enable) {
		this.dgramSend = enable;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableSendComplete(boolean)
	 */
	@Override
	public IpfConfiguration enableSendComplete(boolean passDgramsComplete) {
		this.dgramSendComplete = passDgramsComplete;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableFragments(boolean)
	 */
	@Override
	public IpfConfiguration enableFragments(boolean passFragments) {
		this.fragsPass = passFragments;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableSendIncomplete(boolean)
	 */
	@Override
	public IpfConfiguration enableSendIncomplete(boolean passDgramsIncomplete) {
		this.dgramSendIncomplete = passDgramsIncomplete;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableReassembly(boolean)
	 */
	@Override
	public IpfConfiguration enableReassembly(boolean enable) {
		this.enableReassembly = enable;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#enableTracking(boolean)
	 */
	@Override
	public IpfConfiguration enableTracking(boolean enable) {
		this.enableTracking = enable;

		return this;
	}

	/**
	 * @return the bufferSize
	 */
	@Override
	public int getBufferSize() {
		return bufferSize;
	}

	/**
	 * @return the ipMaxDgramBytes
	 */
	@Override
	public int getMaxDgramBytes() {
		return maxDgramBytes;
	}

	/**
	 * @return the ipfMaxFragTrackCount
	 */
	@Override
	public int getMaxFragmentCount() {
		return maxFragmentCount;
	}

	/**
	 * @return the tableSize
	 */
	@Override
	public int getTableSize() {
		return tableSize;
	}

	/**
	 * @return the timeoutMillis
	 */
	@Override
	public long getTimeoutMilli() {
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
	public boolean isAttachComplete() {
		return fragsPassComplete;
	}

	/**
	 * @return the ipfAttachIncomplete
	 */
	@Override
	public boolean isAttachIncomplete() {
		return fragsPassIncomplete;
	}

	/**
	 * @return the enableIpf
	 */
	@Override
	public boolean isEnabled() {
		return enable;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#isTimeoutOnLast()
	 */
	@Override
	public boolean isTimeoutOnLast() {
		return timeoutOnLast;
	}

	@Override
	public boolean isPassthrough() {
		return dgramSend;
	}

	/**
	 * @return the passDgramsComplete
	 */
	@Override
	public boolean isSendComplete() {
		return dgramSendComplete;
	}

	/**
	 * @return the passFragments
	 */
	@Override
	public boolean isPassFragments() {
		return fragsPass;
	}

	/**
	 * @return the passDgramsIncomplete
	 */
	@Override
	public boolean isSendIncomplete() {
		return dgramSendIncomplete;
	}

	/**
	 * @return the enableIpfReassembly
	 */
	@Override
	public boolean isReassemblyEnabled() {
		return enableReassembly;
	}

	/**
	 * @return the enableIpfTracking
	 */
	@Override
	public boolean isTrackingEnabled() {
		return enableTracking;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setBufferSize(long,
	 *      com.slytechs.protocol.runtime.util.MemoryUnit)
	 */
	@Override
	public IpfConfiguration setBufferSize(long size, MemoryUnit unit) {
		this.bufferSize = unit.toBytesAsInt(size);
		this.tableSize = bufferSize / maxDgramBytes;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setTimeoutOnLast(boolean)
	 */
	@Override
	public IpfConfiguration setTimeoutOnLast(boolean lastOrTimeout) {
		this.timeoutOnLast = lastOrTimeout;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setMaxDgramSize(long,
	 *      com.slytechs.protocol.runtime.util.MemoryUnit)
	 */
	@Override
	public IpfConfiguration setMaxDgramSize(long size, MemoryUnit unit) {
		this.maxDgramBytes = unit.toBytesAsInt(size);
		this.bufferSize = tableSize * maxDgramBytes;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setMaxFragmentCount(int)
	 */
	@Override
	public IpfConfiguration setMaxFragmentCount(int ipfMaxFragTrackCount, CountUnit unit) {
		this.maxFragmentCount = ipfMaxFragTrackCount;
		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setTableSize(long,
	 *      com.slytechs.protocol.runtime.util.CountUnit)
	 */
	@Override
	public IpfConfiguration setTableSize(long size, CountUnit unit) {
		this.tableSize = unit.toCountAsInt(size);
		this.bufferSize = tableSize * maxDgramBytes;

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#setTimeout(long,
	 *      java.util.concurrent.TimeUnit)
	 */
	@Override
	public IpfConfiguration setTimeout(long timeout, TimeUnit unit) {
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
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#usePacketTimesource()
	 */
	@Override
	public IpfConfiguration usePacketTimesource() {
		timeSource = TimestampSource.assignable();

		return this;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.IpfConfiguration#useSystemTimesource()
	 */
	@Override
	public IpfConfiguration useSystemTimesource() {
		timeSource = TimestampSource.system();

		return this;
	}
}
