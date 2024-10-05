/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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

import static com.slytechs.jnet.jnetruntime.util.SystemProperties.*;

import java.util.concurrent.TimeUnit;

import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnet.jnetpcap.IpfConfiguration;
import com.slytechs.jnet.jnetpcap.internal.PacketReceiverConfig;
import com.slytechs.jnet.jnetruntime.time.TimestampSource;
import com.slytechs.jnet.jnetruntime.time.TimestampSource.AssignableTimestampSource;
import com.slytechs.jnet.jnetruntime.time.TimestampUnit;
import com.slytechs.jnet.jnetruntime.util.CountUnit;
import com.slytechs.jnet.jnetruntime.util.MemoryUnit;

/**
 * (Private API) IPF configuration implementation.
 * 
 * @author Mark Bednarczyk
 *
 */
public class IpfConfig extends PacketReceiverConfig implements IpfConfiguration {

	// @formatter:off
	
	/** The max dgram bytes. */
	/* Hashtable and IP reassembler properties */
	private int     maxDgramBytes         = intValue (PROPERTY_IPF_MAX_DGRAM_BYTES,        64,  MemoryUnit.KILOBYTES);
	
	/** The buffer size. */
	private int     bufferSize            = intValue (PROPERTY_IPF_BUFFER_SIZE,            16,  MemoryUnit.MEGABYTES);
	
	/** The table size. */
	private int     tableSize             = intValue (PROPERTY_IPF_TABLE_SIZE,             256, CountUnit.COUNT);
	
	/** The max fragment count. */
	private int     maxFragmentCount      = intValue (PROPERTY_IPF_MAX_FRAGMENT_COUNT,     16,  CountUnit.COUNT);

	/** The timeout millis. */
	/* Timeout Queue properties */
	private long    timeoutMillis         = longValue(PROPERTY_IPF_TIMEOUT,                2000);
	
	/** The timeout on last. */
	private boolean timeoutOnLast         = boolValue(PROPERTY_IPF_TIMEOUT_ON_LAST,        false);
	
	/** The timeout queue size. */
	private int     timeoutQueueSize      = intValue (PROPERTY_IPF_TIMEOUT_QUEUE_SIZE,     256, CountUnit.COUNT);

	/** The enable. */
	/* IPF modes */
	private boolean enable             = boolValue(PROPERTY_IPF_ENABLE,                 false);
	
	/** The enable tracking. */
	private boolean enableTracking     = boolValue(PROPERTY_IPF_ENABLE_TRACKING,        true);
	
	/** The enable reassembly. */
	private boolean enableReassembly   = boolValue(PROPERTY_IPF_ENABLE_REASSEMBLY,      true);

	/** The frags pass. */
	/* Fragment pass-through and reassembly buffer attachment to fragment properties */
	private boolean fragsPass             = boolValue(PROPERTY_IPF_FRAGS_PASS,             false);
	
	/** The frags pass incomplete. */
	private boolean fragsPassIncomplete   = boolValue(PROPERTY_IPF_FRAGS_PASS_INCOMPLETE,  true);
	
	/** The frags pass complete. */
	private boolean fragsPassComplete     = boolValue(PROPERTY_IPF_FRAGS_PASS_COMPLETE,    true);
	
	/** The dgram send. */
	/* Datagram dispatcher send properties - dgrams are inserted into dispatcher stream */
	private boolean dgramSend            = boolValue(PROPERTY_IPF_DGRAMS_SEND,            true);
	
	/** The dgram send incomplete. */
	private boolean dgramSendIncomplete  = boolValue(PROPERTY_IPF_DGRAMS_SEND_INCOMPLETE, false);
	
	/** The dgram send complete. */
	private boolean dgramSendComplete    = boolValue(PROPERTY_IPF_DGRAMS_SEND_COMPLETE,   true);
	// @formatter:on

	/** Initialized in constructor, either system or packet time. */
	private AssignableTimestampSource timeSource;

	/**
	 * Effective or the result of combining of all the main properties and modes.
	 *
	 * @author Mark Bednarczyk
	 */
	public class EffectiveConfig {

		/** The pass. */
		final boolean pass;

		/** The dgrams complete. */
		final boolean dgramsComplete;

		/** The dgrams incomplete. */
		final boolean dgramsIncomplete; // On timeout-duration or timeout-last

		/** The tracking. */
		final boolean tracking;

		/** The pass complete. */
		final boolean passComplete;

		/** The pass incomplete. */
		final boolean passIncomplete; // On timeout-last

		/** The time source. */
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
		 * Gets the time source.
		 *
		 * @return the time source
		 */
		public AssignableTimestampSource getTimeSource() {
			return timeSource;
		}

		/**
		 * Gets the pcap abi.
		 *
		 * @return the pcap abi
		 */
		public PcapHeaderABI getPcapAbi() {
			return abi;
		}

		/**
		 * Gets the timestamp unit.
		 *
		 * @return the timestamp unit
		 */
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
	 * Enable.
	 *
	 * @param enable the enable
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#enable(boolean)
	 */
	@Override
	public IpfConfiguration enable(boolean enable) {
		this.enable = enable;

		return this;
	}

	/**
	 * Enable attach complete.
	 *
	 * @param ipfAttachComplete the ipf attach complete
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#enableAttachComplete(boolean)
	 */
	@Override
	public IpfConfiguration enableAttachComplete(boolean ipfAttachComplete) {
		this.fragsPassComplete = ipfAttachComplete;
		return this;
	}

	/**
	 * Enable attach incomplete.
	 *
	 * @param ipfAttachIncomplete the ipf attach incomplete
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#enableAttachIncomplete(boolean)
	 */
	@Override
	public IpfConfiguration enableAttachIncomplete(boolean ipfAttachIncomplete) {
		this.fragsPassIncomplete = ipfAttachIncomplete;
		return this;
	}

	/**
	 * Enable passthrough.
	 *
	 * @param enable the enable
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#enablePassthrough(boolean)
	 */
	@Override
	public IpfConfiguration enablePassthrough(boolean enable) {
		this.dgramSend = enable;

		return this;
	}

	/**
	 * Enable send complete.
	 *
	 * @param passDgramsComplete the pass dgrams complete
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#enableSendComplete(boolean)
	 */
	@Override
	public IpfConfiguration enableSendComplete(boolean passDgramsComplete) {
		this.dgramSendComplete = passDgramsComplete;
		return this;
	}

	/**
	 * Enable fragments.
	 *
	 * @param passFragments the pass fragments
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#enableFragments(boolean)
	 */
	@Override
	public IpfConfiguration enableFragments(boolean passFragments) {
		this.fragsPass = passFragments;
		return this;
	}

	/**
	 * Enable send incomplete.
	 *
	 * @param passDgramsIncomplete the pass dgrams incomplete
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#enableSendIncomplete(boolean)
	 */
	@Override
	public IpfConfiguration enableSendIncomplete(boolean passDgramsIncomplete) {
		this.dgramSendIncomplete = passDgramsIncomplete;
		return this;
	}

	/**
	 * Enable reassembly.
	 *
	 * @param enable the enable
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#enableReassembly(boolean)
	 */
	@Override
	public IpfConfiguration enableReassembly(boolean enable) {
		this.enableReassembly = enable;

		return this;
	}

	/**
	 * Enable tracking.
	 *
	 * @param enable the enable
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#enableTracking(boolean)
	 */
	@Override
	public IpfConfiguration enableTracking(boolean enable) {
		this.enableTracking = enable;

		return this;
	}

	/**
	 * Gets the buffer size.
	 *
	 * @return the bufferSize
	 */
	@Override
	public int getBufferSize() {
		return bufferSize;
	}

	/**
	 * Gets the max dgram bytes.
	 *
	 * @return the ipMaxDgramBytes
	 */
	@Override
	public int getMaxDgramBytes() {
		return maxDgramBytes;
	}

	/**
	 * Gets the max fragment count.
	 *
	 * @return the ipfMaxFragTrackCount
	 */
	@Override
	public int getMaxFragmentCount() {
		return maxFragmentCount;
	}

	/**
	 * Gets the table size.
	 *
	 * @return the tableSize
	 */
	@Override
	public int getTableSize() {
		return tableSize;
	}

	/**
	 * Gets the timeout milli.
	 *
	 * @return the timeoutMillis
	 */
	@Override
	public long getTimeoutMilli() {
		return timeoutMillis;
	}

	/**
	 * Gets the timeout queue size.
	 *
	 * @return the timeoutQueueSize
	 */
	@Override
	public int getTimeoutQueueSize() {
		return timeoutQueueSize;
	}

	/**
	 * Gets the initialized in constructor, either system or packet time.
	 *
	 * @return the timeSource
	 */
	@Override
	public TimestampSource getTimeSource() {
		return timeSource;
	}

	/**
	 * Checks if is attach complete.
	 *
	 * @return the ipfAttachComplete
	 */
	@Override
	public boolean isAttachComplete() {
		return fragsPassComplete;
	}

	/**
	 * Checks if is attach incomplete.
	 *
	 * @return the ipfAttachIncomplete
	 */
	@Override
	public boolean isAttachIncomplete() {
		return fragsPassIncomplete;
	}

	/**
	 * Checks if is enabled.
	 *
	 * @return the enableIpf
	 */
	@Override
	public boolean isEnabled() {
		return enable;
	}

	/**
	 * Checks if is timeout on last.
	 *
	 * @return true, if is timeout on last
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#isTimeoutOnLast()
	 */
	@Override
	public boolean isTimeoutOnLast() {
		return timeoutOnLast;
	}

	/**
	 * Checks if is passthrough.
	 *
	 * @return true, if is passthrough
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#isPassthrough()
	 */
	@Override
	public boolean isPassthrough() {
		return dgramSend;
	}

	/**
	 * Checks if is send complete.
	 *
	 * @return the passDgramsComplete
	 */
	@Override
	public boolean isSendComplete() {
		return dgramSendComplete;
	}

	/**
	 * Checks if is pass fragments.
	 *
	 * @return the passFragments
	 */
	@Override
	public boolean isPassFragments() {
		return fragsPass;
	}

	/**
	 * Checks if is send incomplete.
	 *
	 * @return the passDgramsIncomplete
	 */
	@Override
	public boolean isSendIncomplete() {
		return dgramSendIncomplete;
	}

	/**
	 * Checks if is reassembly enabled.
	 *
	 * @return the enableIpfReassembly
	 */
	@Override
	public boolean isReassemblyEnabled() {
		return enableReassembly;
	}

	/**
	 * Checks if is tracking enabled.
	 *
	 * @return the enableIpfTracking
	 */
	@Override
	public boolean isTrackingEnabled() {
		return enableTracking;
	}

	/**
	 * Sets the buffer size.
	 *
	 * @param size the size
	 * @param unit the unit
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#setBufferSize(long,
	 *      com.slytechs.jnet.jnetruntime.util.MemoryUnit)
	 */
	@Override
	public IpfConfiguration setBufferSize(long size, MemoryUnit unit) {
		this.bufferSize = unit.toBytesAsInt(size);
		this.tableSize = bufferSize / maxDgramBytes;

		return this;
	}

	/**
	 * Sets the timeout on last.
	 *
	 * @param lastOrTimeout the last or timeout
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#setTimeoutOnLast(boolean)
	 */
	@Override
	public IpfConfiguration setTimeoutOnLast(boolean lastOrTimeout) {
		this.timeoutOnLast = lastOrTimeout;

		return this;
	}

	/**
	 * Sets the max dgram size.
	 *
	 * @param size the size
	 * @param unit the unit
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#setMaxDgramSize(long,
	 *      com.slytechs.jnet.jnetruntime.util.MemoryUnit)
	 */
	@Override
	public IpfConfiguration setMaxDgramSize(long size, MemoryUnit unit) {
		this.maxDgramBytes = unit.toBytesAsInt(size);
		this.bufferSize = tableSize * maxDgramBytes;

		return this;
	}

	/**
	 * Sets the max fragment count.
	 *
	 * @param ipfMaxFragTrackCount the ipf max frag track count
	 * @param unit                 the unit
	 * @return the ipf configuration
	 */
	@Override
	public IpfConfiguration setMaxFragmentCount(int ipfMaxFragTrackCount, CountUnit unit) {
		this.maxFragmentCount = ipfMaxFragTrackCount;
		return this;
	}

	/**
	 * Sets the table size.
	 *
	 * @param size the size
	 * @param unit the unit
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#setTableSize(long,
	 *      com.slytechs.jnet.jnetruntime.util.CountUnit)
	 */
	@Override
	public IpfConfiguration setTableSize(long size, CountUnit unit) {
		this.tableSize = unit.toCountAsInt(size);
		this.bufferSize = tableSize * maxDgramBytes;

		return this;
	}

	/**
	 * Sets the timeout.
	 *
	 * @param timeout the timeout
	 * @param unit    the unit
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#setTimeout(long,
	 *      java.util.concurrent.TimeUnit)
	 */
	@Override
	public IpfConfiguration setTimeout(long timeout, TimeUnit unit) {
		this.timeoutMillis = unit.toMillis(timeout);

		return this;
	}

	/**
	 * Sets the timeout queue size.
	 *
	 * @param timeoutQueueSize the timeoutQueueSize to set
	 * @return the ipf configuration
	 */
	@Override
	public IpfConfiguration setTimeoutQueueSize(int timeoutQueueSize) {
		this.timeoutQueueSize = timeoutQueueSize;

		return this;
	}

	/**
	 * Use packet timesource.
	 *
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#usePacketTimesource()
	 */
	@Override
	public IpfConfiguration usePacketTimesource() {
		timeSource = TimestampSource.assignable();

		return this;
	}

	/**
	 * Use system timesource.
	 *
	 * @return the ipf configuration
	 * @see com.slytechs.jnet.jnetpcap.IpfConfiguration#useSystemTimesource()
	 */
	@Override
	public IpfConfiguration useSystemTimesource() {
		timeSource = TimestampSource.system();

		return this;
	}
}
