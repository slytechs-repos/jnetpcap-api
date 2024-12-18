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

import com.slytechs.jnet.jnetruntime.time.TimestampUnit;
import com.slytechs.jnet.jnetruntime.util.settings.BooleanProperty;
import com.slytechs.jnet.jnetruntime.util.settings.DoubleProperty;
import com.slytechs.jnet.jnetruntime.util.settings.EnumProperty;
import com.slytechs.jnet.jnetruntime.util.settings.LongProperty;
import com.slytechs.jnet.jnetruntime.util.settings.Settings;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class PacketPlayerSettings extends Settings<PacketPlayerSettings> {

	/** The Constant PREFIX. */
	private static final String PREFIX = "packet.player";

	public final BooleanProperty ENABLE = newBooleanProperty("enable", true).loadSystemProperty();
	public final BooleanProperty SYNC = newBooleanProperty("sync", true).loadSystemProperty();
	public final BooleanProperty REWRITE_TIMESTAMP = newBooleanProperty("rewriteTs", true).loadSystemProperty();
	public final DoubleProperty SPEED = newDoubleProperty("speed", 1.).loadSystemProperty();
	public final LongProperty IFG = newLongProperty("ifg").loadSystemProperty();
	public final LongProperty IFG_MIN = newLongProperty("ifgMin").loadSystemProperty();
	public final LongProperty IFG_MAX = newLongProperty("ifgMax").loadSystemProperty();
	public final BooleanProperty IFG_PRESERVE = newBooleanProperty("ifgPreserve", true).loadSystemProperty();
	public final EnumProperty<TimestampUnit> TS_UNIT = newEnumProperty("tsUnit", TimestampUnit.EPOCH_MICRO)
			.loadSystemProperty();

	/**
	 * @param baseName
	 */
	public PacketPlayerSettings() {
		super(PREFIX);
	}

}
