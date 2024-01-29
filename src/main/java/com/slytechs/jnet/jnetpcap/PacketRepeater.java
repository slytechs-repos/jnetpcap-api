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
package com.slytechs.jnet.jnetpcap;

import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.IntSupplier;
import java.util.function.LongSupplier;

import com.slytechs.jnet.jnetruntime.pipeline.AbstractNetProcessor;
import com.slytechs.jnet.jnetruntime.pipeline.NetProcessor;
import com.slytechs.jnet.jnetruntime.pipeline.NetProcessorGroup;
import com.slytechs.jnet.jnetruntime.pipeline.NetProcessorType;
import com.slytechs.jnet.jnetruntime.time.TimestampUnit;
import com.slytechs.jnet.jnetruntime.util.SystemProperties;

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
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public final class PacketRepeater extends AbstractNetProcessor<PacketRepeater> {

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

	/**
	 * Instantiates a new packet repeater.
	 */
	public PacketRepeater(NetProcessorGroup group, int priority) {
		super(group, priority, NetProcessorType.RX_PCAP_RAW);
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
	 * @see com.slytechs.jnet.jnetruntime.pipeline.NetProcessor#sink()
	 */
	@Override
	public Object sink() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.jnetruntime.pipeline.NetProcessor#setup()
	 */
	@Override
	public void setup() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.jnetruntime.pipeline.NetProcessor#dispose()
	 */
	@Override
	public void dispose() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	@Override
	public void link(NetProcessor<?> next) {
		// TODO Auto-generated method stub
		
	}
}
