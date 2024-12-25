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
package com.slytechs.jnet.jnetpcap.api.processors;

import com.slytechs.jnet.platform.api.common.settings.BooleanProperty;
import com.slytechs.jnet.platform.api.common.settings.EnumProperty;
import com.slytechs.jnet.platform.api.common.settings.LongProperty;
import com.slytechs.jnet.platform.api.common.settings.Settings;
import com.slytechs.jnet.platform.api.util.time.TimestampUnit;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class PacketRepeaterSettings extends Settings<PacketRepeaterSettings> {

	/** The Constant PREFIX. */
	private static final String PREFIX = "packet.repeater";

	public final BooleanProperty ENABLE = newBooleanProperty("enable", true).loadSystemProperty();
	public final BooleanProperty REWRITE_TIMESTAMP = newBooleanProperty("rewriteTs", true).loadSystemProperty();
	public final LongProperty REPEAT_COUNT = newLongProperty("repeatCount", 1).loadSystemProperty();
	public final LongProperty IFG = newLongProperty("ifg", 0).loadSystemProperty();
	public final LongProperty IFG_MIN = newLongProperty("ifgMin", 0).loadSystemProperty();
	public final EnumProperty<TimestampUnit> TS_UNIT = newEnumProperty("tsUnit", TimestampUnit.EPOCH_MICRO)
			.loadSystemProperty();

	/**
	 * @param baseName
	 */
	public PacketRepeaterSettings() {
		super(PREFIX);
	}

}
