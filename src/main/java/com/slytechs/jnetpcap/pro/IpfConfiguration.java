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

import java.util.concurrent.ThreadFactory;
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

	/**
	 * Defines if threads created by the default thread factory (and only default
	 * thread factory) are daemon threads (default is true). When a different thread
	 * factory is set, it must define its own {@code Thread.setDaemon(boolean)}
	 * policy.
	 */
	boolean DEFAULT_THREAD_DAEMON = boolValue(IpfConfiguration.PROPERTY_IPF_DEFAULT_THREAD_DAEMON, true);

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
	String PROPERTY_IPF_TIMEOUT_ON_LAST     = "ipf.timeout.onLast";

	/** System property which enables IPF data pass-through/forwarding (default is true). */
	String PROPERTY_IPF_PASS                   = "ipf.pass";
	
	/** System property which enables original IPF fragment pass-through (default is true). */
	String PROPERTY_IPF_PASS_FRAGMENTS         = "ipf.pass.fragments";
	
	/** System property which enables reassembled but incomplete, IPF dgram injection/pass-through (default is false). */
	String PROPERTY_IPF_PASS_DGRAMS_INCOMPLETE = "ipf.pass.dgrams.incomplete";
	
	/** System property which enables reassembled and fully complete, IPF dgram injection/pass-through (default is false). */
	String PROPERTY_IPF_PASS_DGRAMS_COMPLETE   = "ipf.pass.dgrams.complete";
	
	/**
	 *  System property which enables threaded mode. In threaded mode, pcap is called using an internal
	 *  thread and pcap dispatched packets are put on a dispatcher queue. Packets are take from the queue
	 *  and dispatched to the user in user thread. Otherwise, Pcap is called in user thread and packets
	 *  are also dispatched to user in original user thread. 
	 *  */
	String PROPERTY_IPF_THREADED_MODE          = "ipf.threadedMode";
	
	/** The property ipf threaded mode daemon. */
	String PROPERTY_IPF_DEFAULT_THREAD_DAEMON  = "ipf.default.thread.daemon";
	
	/** System property which defines the maximum number of IP fragments which can be tracked at once. */
	String PROPERTY_IPF_MAX_FRAGMENT_COUNT     = "ipf.fragment.maxCount";
	
	/** System property which enables attachment of reassembled dgram to the last IP fragment (default is true). */
	String PROPERTY_IPF_ATTACH_COMPLETE        = "ipf.attach.complete";
	
	/** System property which enables attachment of partially reassembled IP dgram to the last IP fragment (default is true). */
	String PROPERTY_IPF_ATTACH_INCOMPLETE      = "ipf.attach.incomplete";
	
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
	IpfConfiguration enableIpf(boolean enable);

	/**
	 * Sets the ipf attach complete.
	 *
	 * @param enable the ipfAttachComplete to set
	 * @return the ipf configuration
	 */
	IpfConfiguration enableIpfAttachComplete(boolean enable);

	/**
	 * Sets the ipf attach incomplete.
	 *
	 * @param enable the ipfAttachIncomplete to set
	 * @return the ipf configuration
	 */
	IpfConfiguration enableIpfAttachIncomplete(boolean enable);

	IpfConfiguration enableIpfPassthrough(boolean enable);

	/**
	 * Sets the ipf pass complete.
	 *
	 * @param enable the passDgramsComplete to set
	 * @return the ipf configuration
	 */
	IpfConfiguration enableIpfPassthroughComplete(boolean enable);

	/**
	 * Sets the ipf pass fragments.
	 *
	 * @param enable the passFragments to set
	 * @return the ipf configuration
	 */
	IpfConfiguration enableIpfPassthroughFragments(boolean enable);

	/**
	 * Sets the ipf pass incomplete.
	 *
	 * @param enable the passDgramsIncomplete to set
	 * @return the ipf configuration
	 */
	IpfConfiguration enableIpfPassthroughIncomplete(boolean enable);

	/**
	 * Enable ipf reassembly.
	 *
	 * @param enable the enable
	 * @return the ipf configuration
	 */
	IpfConfiguration enableIpfReassembly(boolean enable);

	/**
	 * Enable ipf tracking.
	 *
	 * @param enable the enable
	 * @return the ipf configuration
	 */
	IpfConfiguration enableIpfTracking(boolean enable);

	/**
	 * Enable ipf passthrough dgram threaded.
	 *
	 * @param b the b
	 * @return the ipf configuration
	 */
	IpfConfiguration enableIpfThreadedMode(boolean b);

	/**
	 * Gets the buffer size.
	 *
	 * @return the bufferSize
	 */
	int getIpfBufferSize();

	/**
	 * Gets the ip max dgram bytes.
	 *
	 * @return the ipMaxDgramBytes
	 */
	int getIpfMaxDgramBytes();

	/**
	 * Gets the ipf max frag track count.
	 *
	 * @return the ipfMaxFragTrackCount
	 */
	int getIpfMaxFragmentCount();

	/**
	 * Gets the table size.
	 *
	 * @return the tableSize
	 */
	int getIpfTableSize();

	/**
	 * Gets the timeout millis.
	 *
	 * @return the timeoutMillis
	 */
	long getIpfTimeoutMilli();

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
	boolean isIpfAttachComplete();

	/**
	 * Checks if is ipf attach incomplete.
	 *
	 * @return the ipfAttachIncomplete
	 */
	boolean isIpfAttachIncomplete();

	/**
	 * Checks if is enable ipf.
	 *
	 * @return the enableIpf
	 */
	boolean isIpfEnabled();

	/**
	 * Checks if is ipf incomplete on last.
	 *
	 * @return true, if is ipf incomplete on last
	 */
	boolean isIpfIncompleteOnLast();

	/**
	 * Checks if is ipf passthrough.
	 *
	 * @return true, if is ipf passthrough
	 */
	boolean isIpfPassthrough();

	/**
	 * Checks if is pass dgrams complete.
	 *
	 * @return the passDgramsComplete
	 */
	boolean isIpfPassthroughComplete();

	/**
	 * Checks if is pass dgrams incomplete.
	 *
	 * @return the passDgramsIncomplete
	 */
	boolean isIpfPassthroughIncomplete();

	/**
	 * Checks if is pass fragments.
	 *
	 * @return the passFragments
	 */
	boolean isIpfPassthroughFragments();

	/**
	 * Checks if is enable ipf reassembly.
	 *
	 * @return the enableIpfReassembly
	 */
	boolean isIpfReassemblyEnabled();

	/**
	 * Checks if is enable ipf tracking.
	 *
	 * @return the enableIpfTracking
	 */
	boolean isIpfTrackingEnabled();

	/**
	 * Checks if is ipf passthrough dgram threaded.
	 *
	 * @return true, if is ipf passthrough dgram threaded
	 */
	boolean isIpfThreadedMode();

	/**
	 * Sets the ipf buffer size.
	 *
	 * @param size the size
	 * @param unit the unit
	 * @return the ipf configuration
	 */
	IpfConfiguration setIpfBufferSize(long size, MemoryUnit unit);

	/**
	 * Sets the ipf incomplete on last.
	 *
	 * @param lastOrTimeout the last or timeout
	 * @return the ipf configuration
	 */
	IpfConfiguration setIpfTimeoutOnLast(boolean lastOrTimeout);

	/**
	 * Sets the ip max dgram size.
	 *
	 * @param size the size
	 * @param unit the unit
	 * @return the ipf configuration
	 */
	IpfConfiguration setIpfMaxDgramSize(long size, MemoryUnit unit);

	/**
	 * Sets the ipf max frag track count.
	 *
	 * @param ipfMaxFragTrackCount the ipfMaxFragTrackCount to set
	 * @param unit                 the unit
	 * @return the ipf configuration
	 */
	IpfConfiguration setIpfMaxFragmentCount(int ipfMaxFragTrackCount, CountUnit unit);

	/**
	 * Sets the ipf table size.
	 *
	 * @param size the size
	 * @param unit the unit
	 * @return the ipf configuration
	 */
	IpfConfiguration setIpfTableSize(long size, CountUnit unit);

	/**
	 * Sets the ipf timeout.
	 *
	 * @param timeout the timeout
	 * @param unit    the unit
	 * @return the ipf configuration
	 */
	IpfConfiguration setIpfTimeout(long timeout, TimeUnit unit);

	/**
	 * Use ipf packet timesource.
	 *
	 * @return the ipf configuration
	 */
	IpfConfiguration useIpfPacketTimesource();

	/**
	 * Use ipf system timesource.
	 *
	 * @return the ipf configuration
	 */
	IpfConfiguration useIpfSystemTimesource();

	/**
	 * Use ipf thread facory.
	 *
	 * @param factory the factory
	 * @return the ipf configuration
	 */
	IpfConfiguration setIpfThreadFacory(ThreadFactory factory);

	/**
	 * Gets the timeout queue size.
	 *
	 * @return the timeout queue size
	 */
	int getTimeoutQueueSize();

	/**
	 * Sets the timeout queue size.
	 *
	 * @param size the size
	 * @return the ipf configuration
	 */
	IpfConfiguration setTimeoutQueueSize(int size);

	/**
	 * Gets the thread factory.
	 *
	 * @return the thread factory
	 */
	ThreadFactory getThreadFactory();

}