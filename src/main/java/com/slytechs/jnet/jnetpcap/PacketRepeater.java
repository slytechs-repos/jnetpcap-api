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
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.IntSupplier;
import java.util.function.LongSupplier;

import org.jnetpcap.PcapHandler.OfMemorySegment;

import com.slytechs.jnet.jnetruntime.pipeline.AbstractProcessor;
import com.slytechs.jnet.jnetruntime.pipeline.Pipeline;
import com.slytechs.jnet.jnetruntime.time.TimestampUnit;
import com.slytechs.jnet.jnetruntime.util.config.SystemProperties;

/**
 * A packet repeater pre-processor. The repeater is able to repeat, or reinsert
 * a previously seen packet back into the Pcap Pro packet distream any number of
 * times. This allows every packet to be repeated a certain number of times.
 * <p>
 * You can also add a delay or inter-frame-gap between each of the repeated
 * packets, allowing certain amount of spacing. Optionally, you can also the
 * repeater rewrite the "timestamp" field of the pcap header, so that each
 * packet has an updated timestamp that is different from the original packet.
 * </p>
 *
 * @author Mark Bednarczyk
 */
public final class PacketRepeater
		extends AbstractProcessor<OfMemorySegment<Object>, PacketRepeater>
		implements OfMemorySegment<Object> {

	/** The Constant PREFIX. */
	private static final String PREFIX = "packet.repeater";

	/** The Constant PROPERTY_PACKET_REPEATER_ENABLE. */
	public static final String PROPERTY_PACKET_REPEATER_ENABLE = PREFIX + ".enable";

	/** The Constant PROPERTY_PACKET_REPEATER_REPEAT_COUNT. */
	public static final String PROPERTY_PACKET_REPEATER_REPEAT_COUNT = PREFIX + ".repeatCout";

	/** The Constant PROPERTY_PACKET_REPEATER_DELAY_NANO. */
	public static final String PROPERTY_PACKET_REPEATER_DELAY_NANO = PREFIX + ".delayNano";

	/** The repeat count. */
	private long repeatCount = SystemProperties.longValue(PROPERTY_PACKET_REPEATER_REPEAT_COUNT, 1);

	/** The delay nano. */
	private long ifgForRepeatedNano = SystemProperties.longValue(PROPERTY_PACKET_REPEATER_DELAY_NANO, 1000);

	/** The rewrite timestamp. */
	private boolean rewriteTimestamp;

	/** The min ifg nano. */
	private long minIfgNano;

	/** The timestamp unit. */
	private TimestampUnit timestampUnit = TimestampUnit.PCAP_MICRO;
	
	/** The Constant NAME. */
	public static final String NAME = "packet-repeater";

	/**
	 * Instantiates a new packet repeater.
	 *
	 * @param pipeline the pipeline
	 * @param priority the priority
	 */
	public PacketRepeater(Pipeline<OfMemorySegment<Object>, ?> pipeline, int priority) {
		super(pipeline, priority, NAME, PcapDataType.PCAP_RAW_PACKET);

		name(PREFIX);
	}

	/**
	 * Discard all packets. No packets, including the originals, will be sent
	 * through. Setting a repeat count value after making a call to this method,
	 * will reset the discard flag.
	 *
	 * @return this packet repeater
	 */
	public PacketRepeater discardAllPackets() {
		return discardAllPackets(true);
	}

	/**
	 * Discard all packets, conditionally. No packets, including the originals, will
	 * be sent through. Setting a repeat count value after making a call to this
	 * method, will reset the discard flag.
	 *
	 *
	 * @param discard the discard flag which can be enabled or disabled
	 * @return this packet repeater
	 */
	public PacketRepeater discardAllPackets(boolean discard) {
		if (discard)
			this.repeatCount = -1;

		return this;
	}

	/**
	 * Discard all packets if the discard flag supplier returns true. Causes all
	 * packets, including the original packet to be discarded.
	 *
	 * @param discard a discard flag supplier
	 * @return this packet repeater
	 */
	public PacketRepeater discardAllPackets(BooleanSupplier discard) {
		return discardAllPackets(discard.getAsBoolean());
	}

	/**
	 * Gets the current repeated packet delay or inter-frame-gap (IFG) if any.
	 *
	 * @param unit the time unit requested
	 * @return the delay
	 */
	public long getIfgForRepeated(TimeUnit unit) {
		return unit.convert(ifgForRepeatedNano, TimeUnit.NANOSECONDS);
	}

	/**
	 * Gets the current repeated packet delay or inter-frame-gap if any, with nano
	 * second precision.
	 *
	 * @return the delay nano
	 */
	public long getIfgForRepeatedNano() {
		return ifgForRepeatedNano;
	}

	/**
	 * Gets the repeat count value.
	 *
	 * @return the repeat count
	 */
	public long getRepeatCount() {
		return repeatCount;
	}

	/**
	 * Checks if is rewrite timestamp flag is set.
	 *
	 * @return true, if is rewrite timestamp
	 */
	public boolean isRewriteTimestamp() {
		return this.rewriteTimestamp;
	}

	/**
	 * Rewrite timestamp flag. The rewrite timestamp flag, will rewrite the
	 * timestamp in the pcap header for all repeated packets to reflect the
	 * calculated timestamp based on the timestamp of the original packet and how
	 * much delay was used before the repeated packet is sent.
	 * <p>
	 * This flag has no effect on the original packet. Its timestamp is never
	 * modified, only the repeated packets.
	 * </p>
	 *
	 * @param enable enables the rewrite timestamp flag
	 * @return this packet repeater
	 */
	public PacketRepeater rewriteTimestamp(boolean enable) {
		this.rewriteTimestamp = enable;

		return this;
	}

	/**
	 * Sets the delay or inter-frame-gap between the original packet and all of
	 * subsequent repeated packets.
	 *
	 * @param duration the duration or inter-frame-gap
	 * @param unit     the time unit for the delay
	 * @return this packet repeater
	 */
	public PacketRepeater setIfgForRepeated(long duration, TimeUnit unit) {
		this.ifgForRepeatedNano = unit.toNanos(duration);

		return this;
	}

	/**
	 * Sets the repeat count using a supplier. Each packet captured by pcap is
	 * repeated, not duplicated. The exact original packet is repeatedly sent into
	 * the pcap packet stream. Each of the repeated packets, will be identical to
	 * the original packet being repeated, including its memory addresses for header
	 * and packet data pointers.
	 *
	 * @param count how many times to repeat the original packet, where 0 means 0
	 *              times so only the original packet will be sent, a 1 means 1
	 *              repeat resulting in 2 packets (the original + 1 repeated) will
	 *              be sent, etc.
	 * @return this packet repeater
	 */
	public PacketRepeater setRepeatCount(IntSupplier count) {
		return repeatCount(count.getAsInt());
	}

	/**
	 * Sets the repeat count. Each packet captured by pcap is repeated, not
	 * duplicated. The exact original packet is repeatedly sent into the pcap packet
	 * stream. Each of the repeated packets, will be identical to the original
	 * packet being repeated, including its memory addresses for header and packet
	 * data pointers.
	 *
	 * @param count how many times to repeat the original packet, where 0 means 0
	 *              times so only the original packet will be sent, a 1 means 1
	 *              repeat resulting in 2 packets (the original + 1 repeated) will
	 *              be sent, etc.
	 * @return this packet repeater
	 */
	public PacketRepeater repeatCount(long count) {
		if (count < 0)
			throw new IllegalArgumentException("repeat count can not be negative");

		this.repeatCount = count;

		return this;
	}

	/**
	 * Sets the minimum ifg.
	 *
	 * @param ifg  the ifg
	 * @param unit the unit
	 * @return the packet repeater
	 */
	public PacketRepeater setMinimumIfg(long ifg, TimeUnit unit) {
		this.minIfgNano = Objects.requireNonNull(unit, "unit").toNanos(ifg);

		return this;
	}

	/**
	 * Sets the timestamp unit.
	 *
	 * @param unit the unit
	 * @return the packet repeater
	 */
	public PacketRepeater setTimestampUnit(TimestampUnit unit) {
		this.timestampUnit = Objects.requireNonNull(unit, "unit");

		return this;
	}

	/**
	 * Sets the repeat count using a supplier. Each packet captured by pcap is
	 * repeated, not duplicated. The exact original packet is repeatedly sent into
	 * the pcap packet stream. Each of the repeated packets, will be identical to
	 * the original packet being repeated, including its memory addresses for header
	 * and packet data pointers.
	 *
	 * @param count how many times to repeat the original packet, where 0 means 0
	 *              times so only the original packet will be sent, a 1 means 1
	 *              repeat resulting in 2 packets (the original + 1 repeated) will
	 *              be sent, etc.
	 * @return this packet repeater
	 */
	public PacketRepeater repeatCount(LongSupplier count) {
		return repeatCount(count.getAsLong());
	}

	/**
	 * Gets the minimum ifg nano.
	 *
	 * @return the minIfgNano
	 */
	public long getMinimumIfgNano() {
		return minIfgNano;
	}

	/**
	 * Gets the timestamp unit.
	 *
	 * @return the timestampUnit
	 */
	public TimestampUnit getTimestampUnit() {
		return timestampUnit;
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
		for (long c = 0; c < repeatCount; c++)
			delay();

		outputData().handleSegment(user, header, packet);
	}

	/**
	 * Delay.
	 */
	private void delay() {
		final long MIN_BLOCK = 150_000_000;
		long start = System.nanoTime();
		long end = start + minIfgNano;

		long remaining = end - start;
		do {
			remaining = end - start;

			if (remaining > MIN_BLOCK)
				try {
					delayBlock(end);
				} catch (InterruptedException e) {
					throw new RuntimeException(e);
				}
			else
				delaySpin(end);

		} while (remaining > 0);
	}

	/**
	 * Delay spin.
	 *
	 * @param endNanoTime the end nano time
	 */
	private void delaySpin(long endNanoTime) {
		while (System.nanoTime() < endNanoTime);
	}

	/**
	 * Delay block.
	 *
	 * @param endNanoTime the end nano time
	 * @throws InterruptedException the interrupted exception
	 */
	private void delayBlock(long endNanoTime) throws InterruptedException {
		TimeUnit.NANOSECONDS.sleep(endNanoTime - System.nanoTime());
	}

}
