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
package com.slytechs.jnet.jnetpcap;

import java.lang.foreign.MemorySegment;
import java.util.concurrent.TimeUnit;

import org.jnetpcap.PcapHandler.OfMemorySegment;

import com.slytechs.jnet.jnetruntime.pipeline.AbstractProcessor;
import com.slytechs.jnet.jnetruntime.pipeline.Pipeline;
import com.slytechs.jnet.jnetruntime.util.SystemProperties;

/**
 * The Class PacketDelay.
 *
 * @author Mark Bednarczyk
 */
public final class PacketDelay
		extends AbstractProcessor<OfMemorySegment<Object>, PacketDelay>
		implements OfMemorySegment<Object> {

	/** The Constant PREFIX. */
	private static final String PREFIX = "packet.delay";

	/** The Constant PROPERTY_PACKET_REPEATER_ENABLE. */
	public static final String PROPERTY_PACKET_REPEATER_ENABLE = PREFIX + ".enable";

	/** The Constant PROPERTY_PACKET_REPEATER_DELAY_NANO. */
	public static final String PROPERTY_PACKET_REPEATER_DELAY_NANO = PREFIX + ".delayNano";

	/** The delay nano. */
	private long delayNano = SystemProperties.longValue(PROPERTY_PACKET_REPEATER_DELAY_NANO, 1);

	/** The Constant NAME. */
	public static final String NAME = "packet-delay";

	/**
	 * Instantiates a new packet delay.
	 *
	 * @param pipeline the pipeline
	 * @param priority the priority
	 */
	public PacketDelay(Pipeline<OfMemorySegment<Object>, ?> pipeline, int priority) {
		super(pipeline, priority, NAME, PcapDataType.PCAP_RAW_PACKET);
	}

	/**
	 * Sets the delay.
	 *
	 * @param duration the duration
	 * @param unit     the unit
	 * @return the packet delay
	 */
	public PacketDelay setDelay(long duration, TimeUnit unit) {
		this.delayNano = unit.toNanos(duration);

		return this;
	}

	/**
	 * Gets the delay.
	 *
	 * @param unit the unit
	 * @return the delay
	 */
	public long getDelay(TimeUnit unit) {
		return unit.convert(delayNano, TimeUnit.NANOSECONDS);
	}

	/**
	 * Gets the delay nano.
	 *
	 * @return the delay nano
	 */
	public long getDelayNano() {
		return delayNano;
	}

	/**
	 * Handle segment.
	 *
	 * @param user   the user
	 * @param header the header
	 * @param packet the packet
	 * @see org.jnetpcap.PcapHandler.OfMemorySegment#handleSegment(java.lang.Object,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public void handleSegment(Object user, MemorySegment header, MemorySegment packet) {
		outputData().handleSegment(user, header, packet);
	}

}
