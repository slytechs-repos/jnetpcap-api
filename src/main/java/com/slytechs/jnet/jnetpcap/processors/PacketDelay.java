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
package com.slytechs.jnet.jnetpcap.processors;

import java.lang.foreign.MemorySegment;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import com.slytechs.jnet.jnetpcap.internal.PrePcapPipeline.PreContext;
import com.slytechs.jnet.jnetpcap.processors.PreProcessors.PreProcessorData;
import com.slytechs.jnet.jnetruntime.pipeline.Processor;
import com.slytechs.jnet.jnetruntime.time.NanoTime;

/**
 * A packet processor that introduces configurable delays between packet
 * processing operations. This processor can be used to simulate network
 * conditions, control packet processing rates, or implement traffic shaping in
 * packet processing pipelines.
 * 
 * <p>
 * The delay can be specified using various time units through different
 * constructor overloads and setter methods. The processor maintains the delay
 * settings through an internal {@code PacketDelaySettings} instance.
 * </p>
 * 
 * <p>
 * This processor is part of the pre-processing pipeline and operates at the
 * {@code PreProcessors.PACKET_DELAY_PRIORITY} priority level.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public final class PacketDelay
		extends Processor<PreProcessorData>
		implements PreProcessorData {

	/** The name identifier for this processor. */
	public static final String NAME = "PacketDelay";

	private final PacketDelaySettings settings = new PacketDelaySettings();

	/**
	 * Constructs a new PacketDelay processor with custom settings.
	 *
	 * @param settings the delay settings to be applied to this processor
	 */
	public PacketDelay(PacketDelaySettings settings) {
		super(PreProcessors.PACKET_DELAY_PRIORITY, NAME);
		this.settings.mergeValues(settings);
	}

	/**
	 * Constructs a new PacketDelay processor with specified duration and time unit.
	 *
	 * @param duration the length of the delay
	 * @param unit     the time unit of the delay duration
	 */
	public PacketDelay(long duration, TimeUnit unit) {
		super(PreProcessors.PACKET_DELAY_PRIORITY, NAME);
		setDelay(duration, unit);
	}

	/**
	 * Constructs a new PacketDelay processor with a Java Duration object.
	 *
	 * @param duration the delay duration
	 */
	public PacketDelay(Duration duration) {
		super(PreProcessors.PACKET_DELAY_PRIORITY, NAME);
		setDelay(duration);
	}

	/**
	 * Sets the packet processing delay using a Duration object.
	 *
	 * @param duration the new delay duration
	 * @return this PacketDelay instance for method chaining
	 */
	public PacketDelay setDelay(Duration duration) {
		rwGuard.writeLocked(() -> settings.DELAY_NANO.setLong(duration.toNanos()));

		return this;
	}

	/**
	 * Sets the packet processing delay using a specific time unit.
	 *
	 * @param duration the length of the delay
	 * @param unit     the time unit of the delay duration
	 * @return this PacketDelay instance for method chaining
	 */
	public PacketDelay setDelay(long duration, TimeUnit unit) {
		rwGuard.writeLocked(() -> settings.delayNano(unit.toNanos(duration)));

		return this;
	}

	/**
	 * Retrieves the current delay value converted to the specified time unit.
	 *
	 * @param unit the time unit to convert the delay value to
	 * @return the current delay value in the specified unit
	 */
	public long getDelay(TimeUnit unit) {
		return rwGuard.readLocked(() -> unit.convert(settings.delayNano(), TimeUnit.NANOSECONDS));
	}

	/**
	 * Retrieves the current delay value in nanoseconds.
	 *
	 * @return the current delay value in nanoseconds
	 */
	public long getDelayNano() {
		return rwGuard.readLocked(() -> settings.delayNano());
	}

	/**
	 * Processes a native packet by introducing a configured delay before forwarding
	 * the packet to the next processor in the pipeline.
	 * 
	 * <p>
	 * This method uses {@link NanoTime#delay(long)} to implement precise timing
	 * control. If the thread is interrupted during the delay, the method will
	 * return early with a status code of 0.
	 * </p>
	 *
	 * @param header     the memory segment containing the packet header
	 * @param packet     the memory segment containing the packet data
	 * @param preContext the native context for packet processing
	 * @return the result from the next processor in the pipeline, or 0 if
	 *         interrupted
	 */
	@Override
	public long processNativePacket(MemorySegment header, MemorySegment packet,
			@SuppressWarnings("exports") PreContext preContext) {
		try {
			long nanosDelay = settings.delayNano();

			NanoTime.delay(nanosDelay);

		} catch (InterruptedException e) {
			super.handleError(e, outputData);

			return 0;
		}

		return getOutput().processNativePacket(header, packet, preContext);
	}
}