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
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import com.slytechs.jnet.jnetpcap.PrePcapPipeline.NativeContext;
import com.slytechs.jnet.jnetpcap.PreProcessors.PreProcessorData;
import com.slytechs.jnet.jnetruntime.pipeline.Processor;

/**
 * The Class PacketDelay.
 *
 * @author Mark Bednarczyk
 */
public final class PacketDelay
		extends Processor<PreProcessorData>
		implements PreProcessorData {

	private final PacketDelaySettings settings = new PacketDelaySettings();

	/** The Constant NAME. */
	public static final String NAME = "PacketDelay";

	public PacketDelay(PacketDelaySettings settings) {
		super(PreProcessors.PACKET_DELAY_PRIORITY, NAME);

		this.settings.mergeValues(settings);
	}

	public PacketDelay(long duration, TimeUnit unit) {
		super(PreProcessors.PACKET_DELAY_PRIORITY, NAME);

		setDelay(duration, unit);
	}

	public PacketDelay(Duration duration) {
		super(PreProcessors.PACKET_DELAY_PRIORITY, NAME);

		setDelay(duration);
	}

	/**
	 * Sets the delay.
	 *
	 * @param duration the duration
	 * @param unit     the unit
	 * @return the packet delay
	 */
	public PacketDelay setDelay(Duration duration) {
		settings.DELAY_NANO.setLong(duration.toNanos());

		return this;
	}

	/**
	 * Sets the delay.
	 *
	 * @param duration the duration
	 * @param unit     the unit
	 * @return the packet delay
	 */
	public PacketDelay setDelay(long duration, TimeUnit unit) {
		settings.delayNano(unit.toNanos(duration));

		return this;
	}

	/**
	 * Gets the delay.
	 *
	 * @param unit the unit
	 * @return the delay
	 */
	public long getDelay(TimeUnit unit) {
		return unit.convert(settings.delayNano(), TimeUnit.NANOSECONDS);
	}

	/**
	 * Gets the delay nano.
	 *
	 * @return the delay nano
	 */
	public long getDelayNano() {
		return settings.delayNano();
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.PreProcessors.PreProcessorData#processNativePacket(java.lang.foreign.MemorySegment,
	 *      java.lang.foreign.MemorySegment,
	 *      com.slytechs.jnet.jnetpcap.PrePcapPipeline.NativeContext)
	 */
	@Override
	public int processNativePacket(MemorySegment header, MemorySegment packet, NativeContext context) {
		try {
			long nanosDelay = settings.delayNano();

			PcapUtils.delay(nanosDelay);
		} catch (InterruptedException e) {
			return 0;
		}

		return getOutput().processNativePacket(header, packet, context);
	}

}
