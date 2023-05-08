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

import java.util.concurrent.TimeUnit;

import com.slytechs.protocol.runtime.time.TimestampSource;
import com.slytechs.protocol.runtime.util.CountUnit;
import com.slytechs.protocol.runtime.util.MemoryUnit;

/**
 * IP fragmentation configuration.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public interface IpfConfiguration {

	// @formatter:off
	/** System property which defines the maximum IP datagram size (default is 64KB). */
	String PROPERTY_IPF_MAX_DGRAM_BYTES        = "ipf.dgram.maxBytes";
	
	/** System property which defines the default table size, number of entries (default is 16K). */
	String PROPERTY_IPF_TABLE_SIZE             = "ipf.tableSize";
	
	/** System property which defines the reassembly buffer for IPF (default is 1MB). */
	String PROPERTY_IPF_BUFFER_SIZE            = "ipf.bufferSize";
	
	/** System property which defines timeout period during IPF reassembly/Tracking (default is 2 seconds). */
	String PROPERTY_IPF_TIMEOUT                = "ipf.timeout";
	
	/** The property ipf timeout queue size. */
	String PROPERTY_IPF_TIMEOUT_QUEUE_SIZE     = "ipf.timeout.queueSize";
	
	/** 
	 * System property which determines IPF fragment timeout for incomplete reassembly (default false).
	 * When true, IPF will stop reassembling when last fragment is seen even when Dgram is incomplete.
	 * If false the IPF reassembly will timeout/stop when timeout interval expires.  
	 */
	String PROPERTY_IPF_TIMEOUT_ON_LAST        = "ipf.timeout.onLast";
	
	/** System property which enables original IPF fragment pass-through (default is true). */
	String PROPERTY_IPF_FRAGS_PASS         = "ipf.frags.passthrough";
	
	/** System property which enables IPF data pass-through/forwarding (default is true). */
	String PROPERTY_IPF_DGRAMS_SEND                 = "ipf.dgrams";
	
	/** System property which enables reassembled but incomplete, IPF dgram injection/pass-through (default is false). */
	String PROPERTY_IPF_DGRAMS_SEND_INCOMPLETE      = "ipf.dgrams.incomplete";
	
	/** System property which enables reassembled and fully complete, IPF dgram injection/pass-through (default is false). */
	String PROPERTY_IPF_DGRAMS_SEND_COMPLETE        = "ipf.dgrams.complete";
	
	/** System property which defines the maximum number of IP fragments which can be tracked at once. */
	String PROPERTY_IPF_MAX_FRAGMENT_COUNT     = "ipf.fragment.maxCount";
	
	/** System property which enables attachment of reassembled dgram to the last IP fragment (default is true). */
	String PROPERTY_IPF_FRAGS_PASS_COMPLETE        = "ipf.attach.complete";
	
	/** System property which enables attachment of partially reassembled IP dgram to the last IP fragment (default is true). */
	String PROPERTY_IPF_FRAGS_PASS_INCOMPLETE      = "ipf.attach.incomplete";
	
	/** System property which enables IPF fragment tracking and reassembly (default is false). */
	String PROPERTY_IPF_ENABLE                 = "ipf.enable";
	
	/** System property which enables IPF fragment reassembly (default true). */
	String PROPERTY_IPF_ENABLE_REASSEMBLY      = "ipf.enable.reassembly";
	
	/** System property which enables IPF fragment tracking (default false). */
	String PROPERTY_IPF_ENABLE_TRACKING        = "ipf.enable.tracking";
	// @formatter:on

	/**
	 * Enable ipf.
	 *
	 * @param enable the enable
	 * @return the ipf configuration
	 */
	IpfConfiguration enable(boolean enable);

	/**
	 * Sets the ipf attach complete.
	 *
	 * @param enable the ipfAttachComplete to set
	 * @return the ipf configuration
	 */
	IpfConfiguration enableAttachComplete(boolean enable);

	/**
	 * Sets the ipf attach incomplete.
	 *
	 * @param enable the ipfAttachIncomplete to set
	 * @return the ipf configuration
	 */
	IpfConfiguration enableAttachIncomplete(boolean enable);

	IpfConfiguration enablePassthrough(boolean enable);

	/**
	 * Sets the ipf pass complete.
	 *
	 * @param enable the passDgramsComplete to set
	 * @return the ipf configuration
	 */
	IpfConfiguration enableSendComplete(boolean enable);

	/**
	 * Sets the ipf pass fragments.
	 *
	 * @param enable the passFragments to set
	 * @return the ipf configuration
	 */
	IpfConfiguration enableFragments(boolean enable);

	/**
	 * Sets the ipf pass incomplete.
	 *
	 * @param enable the passDgramsIncomplete to set
	 * @return the ipf configuration
	 */
	IpfConfiguration enableSendIncomplete(boolean enable);

	/**
	 * Enable ipf reassembly.
	 *
	 * @param enable the enable
	 * @return the ipf configuration
	 */
	IpfConfiguration enableReassembly(boolean enable);

	/**
	 * Enable ipf tracking.
	 *
	 * @param enable the enable
	 * @return the ipf configuration
	 */
	IpfConfiguration enableTracking(boolean enable);

	/**
	 * Gets the buffer size.
	 *
	 * @return the bufferSize
	 */
	int getBufferSize();

	/**
	 * Gets the ip max dgram bytes.
	 *
	 * @return the ipMaxDgramBytes
	 */
	int getMaxDgramBytes();

	/**
	 * Gets the ipf max frag track count.
	 *
	 * @return the ipfMaxFragTrackCount
	 */
	int getMaxFragmentCount();

	/**
	 * Gets the table size.
	 *
	 * @return the tableSize
	 */
	int getTableSize();

	/**
	 * Gets the timeout millis.
	 *
	 * @return the timeoutMillis
	 */
	long getTimeoutMilli();

	/**
	 * Gets the timeout queue size.
	 *
	 * @return the timeout queue size
	 */
	int getTimeoutQueueSize();

	/**
	 * Gets the time source.
	 *
	 * @return the timeSource
	 */
	TimestampSource getTimeSource();

	/**
	 * Checks if is ipf attach complete.
	 *
	 * @return the ipfAttachComplete
	 */
	boolean isAttachComplete();

	/**
	 * Checks if is ipf attach incomplete.
	 *
	 * @return the ipfAttachIncomplete
	 */
	boolean isAttachIncomplete();

	/**
	 * Checks if is enable ipf.
	 *
	 * @return the enableIpf
	 */
	boolean isEnabled();

	/**
	 * Checks if is ipf incomplete on last.
	 *
	 * @return true, if is ipf incomplete on last
	 */
	boolean isTimeoutOnLast();

	/**
	 * Checks if is ipf passthrough.
	 *
	 * @return true, if is ipf passthrough
	 */
	boolean isPassthrough();

	/**
	 * Checks if is pass dgrams complete.
	 *
	 * @return the passDgramsComplete
	 */
	boolean isSendComplete();

	/**
	 * Checks if is pass fragments.
	 *
	 * @return the passFragments
	 */
	boolean isPassFragments();

	/**
	 * Checks if is pass dgrams incomplete.
	 *
	 * @return the passDgramsIncomplete
	 */
	boolean isSendIncomplete();

	/**
	 * Checks if is enable ipf reassembly.
	 *
	 * @return the enableIpfReassembly
	 */
	boolean isReassemblyEnabled();

	/**
	 * Checks if is enable ipf tracking.
	 *
	 * @return the enableIpfTracking
	 */
	boolean isTrackingEnabled();

	/**
	 * Sets the ipf buffer size.
	 *
	 * @param size the size
	 * @param unit the unit
	 * @return the ipf configuration
	 */
	IpfConfiguration setBufferSize(long size, MemoryUnit unit);

	/**
	 * Sets the ip max dgram size.
	 *
	 * @param size the size
	 * @param unit the unit
	 * @return the ipf configuration
	 */
	IpfConfiguration setMaxDgramSize(long size, MemoryUnit unit);

	/**
	 * Sets the ipf max frag track count.
	 *
	 * @param ipfMaxFragTrackCount the ipfMaxFragTrackCount to set
	 * @param unit                 the unit
	 * @return the ipf configuration
	 */
	IpfConfiguration setMaxFragmentCount(int ipfMaxFragTrackCount, CountUnit unit);

	/**
	 * Sets the ipf table size.
	 *
	 * @param size the size
	 * @param unit the unit
	 * @return the ipf configuration
	 */
	IpfConfiguration setTableSize(long size, CountUnit unit);

	/**
	 * Sets the ipf timeout.
	 *
	 * @param timeout the timeout
	 * @param unit    the unit
	 * @return the ipf configuration
	 */
	IpfConfiguration setTimeout(long timeout, TimeUnit unit);

	/**
	 * Sets the ipf incomplete on last.
	 *
	 * @param lastOrTimeout the last or timeout
	 * @return the ipf configuration
	 */
	IpfConfiguration setTimeoutOnLast(boolean lastOrTimeout);

	/**
	 * Sets the timeout queue size.
	 *
	 * @param size the size
	 * @return the ipf configuration
	 */
	IpfConfiguration setTimeoutQueueSize(int size);

	/**
	 * Use ipf packet timesource.
	 *
	 * @return the ipf configuration
	 */
	IpfConfiguration usePacketTimesource();

	/**
	 * Use ipf system timesource.
	 *
	 * @return the ipf configuration
	 */
	IpfConfiguration useSystemTimesource();

}