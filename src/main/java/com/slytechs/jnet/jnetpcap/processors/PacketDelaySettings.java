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

import com.slytechs.jnet.jnetruntime.util.settings.BooleanProperty;
import com.slytechs.jnet.jnetruntime.util.settings.LongProperty;
import com.slytechs.jnet.jnetruntime.util.settings.Settings;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class PacketDelaySettings extends Settings<PacketDelaySettings> {

	private static final String PREFIX = "packet.delay";

	public final BooleanProperty ENABLE = newBooleanProperty("enable", true);
	public final LongProperty DELAY_NANO = newLongProperty("delayNano", 0).loadSystemProperty();

	/**
	 * @param baseName
	 */
	public PacketDelaySettings() {
		super(PREFIX);
	}

	public long delayNano() {
		return DELAY_NANO.getLong();
	}

	public PacketDelaySettings delayNano(long newValue) {
		DELAY_NANO.setLong(newValue);

		return this;
	}
}
