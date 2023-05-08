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
package com.slytechs.jnetpcap.pro;

import static com.slytechs.protocol.runtime.util.SystemProperties.*;

import java.util.concurrent.TimeUnit;

import com.slytechs.jnetpcap.pro.PcapConfigurator.PostProcessor;
import com.slytechs.jnetpcap.pro.internal.ipf.IpfDispatcher;
import com.slytechs.protocol.runtime.time.TimestampSource;
import com.slytechs.protocol.runtime.time.TimestampSource.AssignableTimestampSource;
import com.slytechs.protocol.runtime.time.TimestampUnit;
import com.slytechs.protocol.runtime.util.CountUnit;
import com.slytechs.protocol.runtime.util.MemoryUnit;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class IpfReassembler extends PcapConfigurator<IpfReassembler> implements PostProcessor {

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
	
	/* Hashtable and IP reassembler properties */
	private int     maxDgramBytes         = intValue (PROPERTY_IPF_MAX_DGRAM_BYTES,        64,  MemoryUnit.KILOBYTES);
	private int     bufferSize            = intValue (PROPERTY_IPF_BUFFER_SIZE,            16,  MemoryUnit.MEGABYTES);
	private int     tableSize             = intValue (PROPERTY_IPF_TABLE_SIZE,             256, CountUnit.COUNT);
	private int     maxFragmentCount      = intValue (PROPERTY_IPF_MAX_FRAGMENT_COUNT,     16,  CountUnit.COUNT);

	/* Timeout Queue properties */
	private long    timeoutMilli         = longValue(PROPERTY_IPF_TIMEOUT,                2000);
	private boolean timeoutOnLast         = boolValue(PROPERTY_IPF_TIMEOUT_ON_LAST,        false);
	private int     timeoutQueueSize      = intValue (PROPERTY_IPF_TIMEOUT_QUEUE_SIZE,     256, CountUnit.COUNT);

	/* IPF modes */
	private boolean trackingEnabled       = boolValue(PROPERTY_IPF_ENABLE_TRACKING,        true);
	private boolean reassemblyEnabled     = boolValue(PROPERTY_IPF_ENABLE_REASSEMBLY,      true);

	/* Fragment pass-through and reassembly buffer attachment to fragment properties */
	private boolean passthrough           = boolValue(PROPERTY_IPF_PASSTHROUGH,             false);
	private boolean attachIncomplete      = boolValue(PROPERTY_IPF_ATTACH_INCOMPLETE,  true);
	private boolean attachComplete        = boolValue(PROPERTY_IPF_ATTACH_COMPLETE,    true);
	
	/* Datagram dispatcher send properties - dgrams are inserted into dispatcher stream */
	private boolean send                  = boolValue(PROPERTY_IPF_DGRAMS_SEND,            true);
	private boolean sendIncomplete        = boolValue(PROPERTY_IPF_DGRAMS_SEND_INCOMPLETE, false);
	private boolean sendComplete          = boolValue(PROPERTY_IPF_DGRAMS_SEND_COMPLETE,   true);
	// @formatter:on

	private AssignableTimestampSource timeSource;

	/**
	 * Effective or the result of combining of all the main properties and modes
	 */
	public class EffectiveConfig {

		public final boolean pass;
		public final boolean dgramsComplete;
		public final boolean dgramsIncomplete; // On timeout-duration or timeout-last
		public final boolean tracking;
		public final boolean passComplete;
		public final boolean passIncomplete; // On timeout-last
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
		 * 
		 */
		public AssignableTimestampSource getTimeSource() {
			return timeSource;
		}

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
	 * @param properyPrefix
	 * @param factory
	 */
	public IpfReassembler() {
		super(PREFIX, IpfDispatcher::newInstance);
	}

	public IpfReassembler enableAttachComplete(boolean attachComplete) {
		this.attachComplete = attachComplete;
		return this;
	}

	public IpfReassembler enableAttachIncomplete(boolean attachIncomplete) {
		this.attachIncomplete = attachIncomplete;
		return this;
	}

	public IpfReassembler enablePassthrough(boolean passthrough) {
		this.passthrough = passthrough;
		return this;
	}

	public IpfReassembler enableReassembly(boolean reassemblyEnabled) {
		this.reassemblyEnabled = reassemblyEnabled;
		return this;
	}

	public IpfReassembler enableSend(boolean send) {
		this.send = send;
		return this;
	}

	public IpfReassembler enableSendComplete(boolean sendComplete) {
		this.sendComplete = sendComplete;
		return this;
	}

	public IpfReassembler enableSendIncomplete(boolean sendIncomplete) {
		this.sendIncomplete = sendIncomplete;
		return this;
	}

	public IpfReassembler enableTracking(boolean trackingEnabled) {
		this.trackingEnabled = trackingEnabled;
		return this;
	}

	public int getBufferSize() {
		return bufferSize;
	}

	public int getMaxDgramBytes() {
		return maxDgramBytes;
	}

	public int getMaxFragmentCount() {
		return maxFragmentCount;
	}

	public int getTableSize() {
		return tableSize;
	}

	public long getTimeoutMilli() {
		return timeoutMilli;
	}

	public int getTimeoutQueueSize() {
		return timeoutQueueSize;
	}

	public TimestampSource getTimeSource() {
		return timeSource;
	}

	public boolean isAttachComplete() {
		return attachComplete;
	}

	public boolean isAttachIncomplete() {
		return attachIncomplete;
	}

	public boolean isPassthrough() {
		return passthrough;
	}

	public boolean isReassemblyEnabled() {
		return reassemblyEnabled;
	}

	public boolean isSend() {
		return send;
	}

	public boolean isSendComplete() {
		return sendComplete;
	}

	public boolean isSendIncomplete() {
		return sendIncomplete;
	}

	public boolean isTimeoutOnLast() {
		return timeoutOnLast;
	}

	public boolean isTrackingEnabled() {
		return trackingEnabled;
	}

	public IpfReassembler setBufferSize(int bufferSize) {
		return setBufferSize(bufferSize, MemoryUnit.BYTES);
	}

	public IpfReassembler setBufferSize(int bufferSize, MemoryUnit unit) {
		this.bufferSize = unit.toBytesAsInt(bufferSize);
		return this;
	}

	public IpfReassembler setMaxDgramSize(int maxDgramBytes) {
		return setMaxDgramSize(maxDgramBytes, MemoryUnit.BYTES);
	}

	public IpfReassembler setMaxDgramSize(int maxDgramBytes, MemoryUnit unit) {
		this.maxDgramBytes = unit.toBytesAsInt(maxDgramBytes);
		return this;
	}

	public IpfReassembler setTableMaxFragmentCount(int maxFragmentCount) {
		this.maxFragmentCount = maxFragmentCount;
		return this;
	}

	public IpfReassembler setTableSize(int tableSize) {
		return setTableSize(tableSize, CountUnit.COUNT);
	}

	public IpfReassembler setTableSize(int tableSize, CountUnit unit) {
		this.tableSize = unit.toCountAsInt(tableSize);
		return this;
	}

	public IpfReassembler setTimeout(long duration, TimeUnit unit) {
		return setTimeoutMilli(unit.toMillis(duration));
	}

	public IpfReassembler setTimeoutMilli(long timeoutMilli) {
		this.timeoutMilli = timeoutMilli;
		return this;
	}

	public IpfReassembler setTimeoutOnLast(boolean timeoutOnLast) {
		this.timeoutOnLast = timeoutOnLast;
		return this;
	}

	public IpfReassembler setTimeoutQueueSize(int timeoutQueueSize) {
		return setTimeoutQueueSize(timeoutQueueSize, CountUnit.COUNT);
	}

	public IpfReassembler setTimeoutQueueSize(int timeoutQueueSize, CountUnit unit) {
		this.timeoutQueueSize = unit.toCountAsInt(timeoutQueueSize);
		return this;
	}

	public IpfReassembler usePacketTimesource() {
		timeSource = TimestampSource.assignable();

		return this;
	}

	public IpfReassembler useSystemTimesource() {
		timeSource = TimestampSource.system();

		return this;
	}
}
