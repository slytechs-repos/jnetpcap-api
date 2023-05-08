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

import com.slytechs.jnetpcap.pro.PcapConfigurator.PreProcessor;
import com.slytechs.jnetpcap.pro.internal.PacketDelayPreProcessor;
import com.slytechs.protocol.runtime.util.SystemProperties;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public final class PacketDelay extends PcapConfigurator<PacketDelay> implements PreProcessor {

	private static final String PREFIX = "packet.delay";
	public static final String PROPERTY_PACKET_REPEATER_ENABLE = PREFIX + ".enable";
	public static final String PROPERTY_PACKET_REPEATER_DELAY_NANO = PREFIX + ".delayNano";

	private long delayNano = SystemProperties.longValue(PROPERTY_PACKET_REPEATER_DELAY_NANO, 1);

	public PacketDelay() {
		super(PREFIX, PacketDelayPreProcessor::new);
	}

	public PacketDelay setDelay(long duration, TimeUnit unit) {
		this.delayNano = unit.toNanos(duration);

		return this;
	}

	public long getDelay(TimeUnit unit) {
		return unit.convert(delayNano, TimeUnit.NANOSECONDS);
	}

	public long getDelayNano() {
		return delayNano;
	}
}
