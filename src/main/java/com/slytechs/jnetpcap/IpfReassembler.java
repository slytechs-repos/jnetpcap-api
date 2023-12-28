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
package com.slytechs.jnetpcap;

import static com.slytechs.protocol.runtime.util.SystemProperties.*;

import java.util.concurrent.TimeUnit;

import com.slytechs.jnetpcap.PcapProConfigurator.PostRxProcessor;
import com.slytechs.jnetpcap.internal.ipf.IpfDispatcher;
import com.slytechs.protocol.runtime.time.TimestampSource;
import com.slytechs.protocol.runtime.time.TimestampSource.AssignableTimestampSource;
import com.slytechs.protocol.runtime.time.TimestampUnit;
import com.slytechs.protocol.runtime.util.CountUnit;
import com.slytechs.protocol.runtime.util.MemoryUnit;

/**
 * The Class IpfReassembler.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class IpfReassembler extends PcapProConfigurator<IpfReassembler> implements PostRxProcessor {

	/** The Constant PREFIX. */
	private static final String PREFIX = "ipf";

	// @formatter:off
	/** System property which defines the maximum IP datagram size (default is 64KB). */
	public static final String PROPERTY_IPF_MAX_DGRAM_BYTES        = "ipf.dgram.maxBytes";
	
	/** System property which defines the default table size, number of entries (default is 16K). */
	public static final String PROPERTY_IPF_TABLE_SIZE             = "ipf.tableSize";
	
	/** System property which defines the reassembly buffer for IPF (default is 1MB). */
	public static final String PROPERTY_IPF_BUFFER_SIZE            = "ipf.bufferSize";
	
	/** System property which defines timeout period during IPF reassembly/Tracking (default is 2 seconds). */
	public static final String PROPERTY_IPF_TIMEOUT                = "ipf.timeout";
	
	/** The property ipf timeout queue size. */
	public static final String PROPERTY_IPF_TIMEOUT_QUEUE_SIZE     = "ipf.timeout.queueSize";
	
	/** 
	 * System property which determines IPF fragment timeout for incomplete reassembly (default false).
	 * When true, IPF will stop reassembling when last fragment is seen even when Dgram is incomplete.
	 * If false the IPF reassembly will timeout/stop when timeout interval expires.  
	 */
	public static final String PROPERTY_IPF_TIMEOUT_ON_LAST             = "ipf.timeout.onLast";
	
	/** System property which enables original IPF fragment pass-through (default is true). */
	public static final String PROPERTY_IPF_PASSTHROUGH                 = "ipf.frags.passthrough";
	
	/** System property which enables IPF data pass-through/forwarding (default is true). */
	public static final String PROPERTY_IPF_DGRAMS_SEND                 = "ipf.dgrams.send";
	
	/** System property which enables reassembled but incomplete, IPF dgram injection/pass-through (default is false). */
	public static final String PROPERTY_IPF_DGRAMS_SEND_INCOMPLETE      = "ipf.dgrams.send.incomplete";
	
	/** System property which enables reassembled and fully complete, IPF dgram injection/pass-through (default is false). */
	public static final String PROPERTY_IPF_DGRAMS_SEND_COMPLETE        = "ipf.dgrams.send.complete";
	
	/** System property which defines the maximum number of IP fragments which can be tracked at once. */
	public static final String PROPERTY_IPF_MAX_FRAGMENT_COUNT          = "ipf.fragment.maxCount";
	
	/** System property which enables attachment of reassembled dgram to the last IP fragment (default is true). */
	public static final String PROPERTY_IPF_ATTACH_COMPLETE             = "ipf.attach.complete";
	
	/** System property which enables attachment of partially reassembled IP dgram to the last IP fragment (default is true). */
	public static final String PROPERTY_IPF_ATTACH_INCOMPLETE           = "ipf.attach.incomplete";
	
	/** System property which enables IPF fragment tracking and reassembly (default is false). */
	public static final String PROPERTY_IPF_ENABLE                      = "ipf.enable";
	
	/** System property which enables IPF fragment reassembly (default true). */
	public static final String PROPERTY_IPF_ENABLE_REASSEMBLY           = "ipf.enable.reassembly";
	
	/** System property which enables IPF fragment tracking (default false). */
	public static final String PROPERTY_IPF_ENABLE_TRACKING             = "ipf.enable.tracking";
	// @formatter:on

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

	/** The timeout milli. */
	/* Timeout Queue properties */
	private long    timeoutMilli         = longValue(PROPERTY_IPF_TIMEOUT,                2000);
	
	/** The timeout on last. */
	private boolean timeoutOnLast         = boolValue(PROPERTY_IPF_TIMEOUT_ON_LAST,        false);
	
	/** The timeout queue size. */
	private int     timeoutQueueSize      = intValue (PROPERTY_IPF_TIMEOUT_QUEUE_SIZE,     256, CountUnit.COUNT);

	/** The tracking enabled. */
	/* IPF modes */
	private boolean trackingEnabled       = boolValue(PROPERTY_IPF_ENABLE_TRACKING,        false);
	
	/** The reassembly enabled. */
	private boolean reassemblyEnabled     = boolValue(PROPERTY_IPF_ENABLE_REASSEMBLY,      true);

	/** The passthrough. */
	/* Fragment pass-through and reassembly buffer attachment to fragment properties */
	private boolean passthrough           = boolValue(PROPERTY_IPF_PASSTHROUGH,             false);
	
	/** The attach incomplete. */
	private boolean attachIncomplete      = boolValue(PROPERTY_IPF_ATTACH_INCOMPLETE,  false);
	
	/** The attach complete. */
	private boolean attachComplete        = boolValue(PROPERTY_IPF_ATTACH_COMPLETE,    false);
	
	/** The send. */
	/* Datagram dispatcher send properties - dgrams are inserted into dispatcher stream */
	private boolean send                  = boolValue(PROPERTY_IPF_DGRAMS_SEND,            true);
	
	/** The send incomplete. */
	private boolean sendIncomplete        = boolValue(PROPERTY_IPF_DGRAMS_SEND_INCOMPLETE, false);
	
	/** The send complete. */
	private boolean sendComplete          = boolValue(PROPERTY_IPF_DGRAMS_SEND_COMPLETE,   true);
	// @formatter:on

	/** The time source. */
	private AssignableTimestampSource timeSource;

	/**
	 * Effective or the result of combining of all the main properties and modes.
	 */
	public class EffectiveConfig {

		/** The pass. */
		public final boolean pass;
		
		/** The dgrams complete. */
		public final boolean dgramsComplete;
		
		/** The dgrams incomplete. */
		public final boolean dgramsIncomplete; // On timeout-duration or timeout-last
		
		/** The tracking. */
		public final boolean tracking;
		
		/** The pass complete. */
		public final boolean passComplete;
		
		/** The pass incomplete. */
		public final boolean passIncomplete; // On timeout-last
		
		/** The time source. */
		public final AssignableTimestampSource timeSource;

		/**
		 * Compute an effective configuration. Based on all of the configuration
		 * options, compute which modes and options are actu
		 */
		EffectiveConfig() {
			this.pass = passthrough;
			this.passComplete = reassemblyEnabled && attachComplete;
			this.passIncomplete = reassemblyEnabled && attachIncomplete && timeoutOnLast;

			this.dgramsComplete = send && reassemblyEnabled && sendComplete;
			this.dgramsIncomplete = send && reassemblyEnabled && sendIncomplete;

			this.tracking = trackingEnabled && passthrough;
			this.timeSource = IpfReassembler.this.timeSource;
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
		 * Gets the timestamp unit.
		 *
		 * @return the timestamp unit
		 */
		public TimestampUnit getTimestampUnit() {
			return TimestampUnit.PCAP_MICRO;
		}
	}

	/**
	 * Compute effective config.
	 *
	 * @return the effective config
	 */
	public EffectiveConfig computeEffectiveConfig() {
		return new EffectiveConfig();
	}

	/**
	 * Instantiates a new ipf reassembler.
	 */
	public IpfReassembler() {
		super(PREFIX, IpfDispatcher::newInstance);

		useSystemTimesource();
	}

	/**
	 * Enable attach complete.
	 *
	 * @param attachComplete the attach complete
	 * @return the ipf reassembler
	 */
	public IpfReassembler enableAttachComplete(boolean attachComplete) {
		this.attachComplete = attachComplete;
		return this;
	}

	/**
	 * Enable attach incomplete.
	 *
	 * @param attachIncomplete the attach incomplete
	 * @return the ipf reassembler
	 */
	public IpfReassembler enableAttachIncomplete(boolean attachIncomplete) {
		this.attachIncomplete = attachIncomplete;
		return this;
	}

	/**
	 * Enable passthrough.
	 *
	 * @param passthrough the passthrough
	 * @return the ipf reassembler
	 */
	public IpfReassembler enablePassthrough(boolean passthrough) {
		this.passthrough = passthrough;
		return this;
	}

	/**
	 * Enable reassembly.
	 *
	 * @param reassemblyEnabled the reassembly enabled
	 * @return the ipf reassembler
	 */
	public IpfReassembler enableReassembly(boolean reassemblyEnabled) {
		this.reassemblyEnabled = reassemblyEnabled;
		return this;
	}

	/**
	 * Enable send.
	 *
	 * @param send the send
	 * @return the ipf reassembler
	 */
	public IpfReassembler enableSend(boolean send) {
		this.send = send;
		return this;
	}

	/**
	 * Enable send complete.
	 *
	 * @param sendComplete the send complete
	 * @return the ipf reassembler
	 */
	public IpfReassembler enableSendComplete(boolean sendComplete) {
		this.sendComplete = sendComplete;
		return this;
	}

	/**
	 * Enable send incomplete.
	 *
	 * @param sendIncomplete the send incomplete
	 * @return the ipf reassembler
	 */
	public IpfReassembler enableSendIncomplete(boolean sendIncomplete) {
		this.sendIncomplete = sendIncomplete;
		return this;
	}

	/**
	 * Enable tracking.
	 *
	 * @param trackingEnabled the tracking enabled
	 * @return the ipf reassembler
	 */
	public IpfReassembler enableTracking(boolean trackingEnabled) {
		this.trackingEnabled = trackingEnabled;
		return this;
	}

	/**
	 * Gets the buffer size.
	 *
	 * @return the buffer size
	 */
	public int getBufferSize() {
		return bufferSize;
	}

	/**
	 * Gets the max dgram bytes.
	 *
	 * @return the max dgram bytes
	 */
	public int getMaxDgramBytes() {
		return maxDgramBytes;
	}

	/**
	 * Gets the max fragment count.
	 *
	 * @return the max fragment count
	 */
	public int getMaxFragmentCount() {
		return maxFragmentCount;
	}

	/**
	 * Gets the table size.
	 *
	 * @return the table size
	 */
	public int getTableSize() {
		return tableSize;
	}

	/**
	 * Gets the timeout milli.
	 *
	 * @return the timeout milli
	 */
	public long getTimeoutMilli() {
		return timeoutMilli;
	}

	/**
	 * Gets the timeout queue size.
	 *
	 * @return the timeout queue size
	 */
	public int getTimeoutQueueSize() {
		return timeoutQueueSize;
	}

	/**
	 * Gets the time source.
	 *
	 * @return the time source
	 */
	public TimestampSource getTimeSource() {
		return timeSource;
	}

	/**
	 * Checks if is attach complete.
	 *
	 * @return true, if is attach complete
	 */
	public boolean isAttachComplete() {
		return attachComplete;
	}

	/**
	 * Checks if is attach incomplete.
	 *
	 * @return true, if is attach incomplete
	 */
	public boolean isAttachIncomplete() {
		return attachIncomplete;
	}

	/**
	 * Checks if is passthrough.
	 *
	 * @return true, if is passthrough
	 */
	public boolean isPassthrough() {
		return passthrough;
	}

	/**
	 * Checks if is reassembly enabled.
	 *
	 * @return true, if is reassembly enabled
	 */
	public boolean isReassemblyEnabled() {
		return reassemblyEnabled;
	}

	/**
	 * Checks if is send.
	 *
	 * @return true, if is send
	 */
	public boolean isSend() {
		return send;
	}

	/**
	 * Checks if is send complete.
	 *
	 * @return true, if is send complete
	 */
	public boolean isSendComplete() {
		return sendComplete;
	}

	/**
	 * Checks if is send incomplete.
	 *
	 * @return true, if is send incomplete
	 */
	public boolean isSendIncomplete() {
		return sendIncomplete;
	}

	/**
	 * Checks if is timeout on last.
	 *
	 * @return true, if is timeout on last
	 */
	public boolean isTimeoutOnLast() {
		return timeoutOnLast;
	}

	/**
	 * Checks if is tracking enabled.
	 *
	 * @return true, if is tracking enabled
	 */
	public boolean isTrackingEnabled() {
		return trackingEnabled;
	}

	/**
	 * Sets the buffer size.
	 *
	 * @param bufferSize the buffer size
	 * @return the ipf reassembler
	 */
	public IpfReassembler setBufferSize(int bufferSize) {
		return setBufferSize(bufferSize, MemoryUnit.BYTES);
	}

	/**
	 * Sets the buffer size.
	 *
	 * @param bufferSize the buffer size
	 * @param unit       the unit
	 * @return the ipf reassembler
	 */
	public IpfReassembler setBufferSize(int bufferSize, MemoryUnit unit) {
		this.bufferSize = unit.toBytesAsInt(bufferSize);
		return this;
	}

	/**
	 * Sets the max dgram size.
	 *
	 * @param maxDgramBytes the max dgram bytes
	 * @return the ipf reassembler
	 */
	public IpfReassembler setMaxDgramSize(int maxDgramBytes) {
		return setMaxDgramSize(maxDgramBytes, MemoryUnit.BYTES);
	}

	/**
	 * Sets the max dgram size.
	 *
	 * @param maxDgramBytes the max dgram bytes
	 * @param unit          the unit
	 * @return the ipf reassembler
	 */
	public IpfReassembler setMaxDgramSize(int maxDgramBytes, MemoryUnit unit) {
		this.maxDgramBytes = unit.toBytesAsInt(maxDgramBytes);
		return this;
	}

	/**
	 * Sets the table max fragment count.
	 *
	 * @param maxFragmentCount the max fragment count
	 * @return the ipf reassembler
	 */
	public IpfReassembler setTableMaxFragmentCount(int maxFragmentCount) {
		this.maxFragmentCount = maxFragmentCount;
		return this;
	}

	/**
	 * Sets the table size.
	 *
	 * @param tableSize the table size
	 * @return the ipf reassembler
	 */
	public IpfReassembler setTableSize(int tableSize) {
		return setTableSize(tableSize, CountUnit.COUNT);
	}

	/**
	 * Sets the table size.
	 *
	 * @param tableSize the table size
	 * @param unit      the unit
	 * @return the ipf reassembler
	 */
	public IpfReassembler setTableSize(int tableSize, CountUnit unit) {
		this.tableSize = unit.toCountAsInt(tableSize);
		return this;
	}

	/**
	 * Sets the timeout.
	 *
	 * @param duration the duration
	 * @param unit     the unit
	 * @return the ipf reassembler
	 */
	public IpfReassembler setTimeout(long duration, TimeUnit unit) {
		return setTimeoutMilli(unit.toMillis(duration));
	}

	/**
	 * Sets the timeout milli.
	 *
	 * @param timeoutMilli the timeout milli
	 * @return the ipf reassembler
	 */
	public IpfReassembler setTimeoutMilli(long timeoutMilli) {
		this.timeoutMilli = timeoutMilli;
		return this;
	}

	/**
	 * Sets the timeout on last.
	 *
	 * @param timeoutOnLast the timeout on last
	 * @return the ipf reassembler
	 */
	public IpfReassembler setTimeoutOnLast(boolean timeoutOnLast) {
		this.timeoutOnLast = timeoutOnLast;
		return this;
	}

	/**
	 * Sets the timeout queue size.
	 *
	 * @param timeoutQueueSize the timeout queue size
	 * @return the ipf reassembler
	 */
	public IpfReassembler setTimeoutQueueSize(int timeoutQueueSize) {
		return setTimeoutQueueSize(timeoutQueueSize, CountUnit.COUNT);
	}

	/**
	 * Sets the timeout queue size.
	 *
	 * @param timeoutQueueSize the timeout queue size
	 * @param unit             the unit
	 * @return the ipf reassembler
	 */
	public IpfReassembler setTimeoutQueueSize(int timeoutQueueSize, CountUnit unit) {
		this.timeoutQueueSize = unit.toCountAsInt(timeoutQueueSize);
		return this;
	}

	/**
	 * Use packet timesource.
	 *
	 * @return the ipf reassembler
	 */
	public IpfReassembler usePacketTimesource() {
		timeSource = TimestampSource.assignable();

		return this;
	}

	/**
	 * Use system timesource.
	 *
	 * @return the ipf reassembler
	 */
	public IpfReassembler useSystemTimesource() {
		timeSource = TimestampSource.system();

		return this;
	}
}
