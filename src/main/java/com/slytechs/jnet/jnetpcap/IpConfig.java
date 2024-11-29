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

import com.slytechs.jnet.jnetpcap.IpConfig.IpProperty;
import com.slytechs.jnet.jnetruntime.util.MemoryUnit;
import com.slytechs.jnet.jnetruntime.util.config.NetConfig;
import com.slytechs.jnet.jnetruntime.util.config.NetProperty;

/**
 * @author Mark Bednarczyk
 *
 */
public class IpConfig extends NetConfig<IpProperty, IpConfig> {

	private static final String PREFIX = "protocol.ip";

	public enum IpProperty implements NetProperty {

		NAME("ip-config"),
		ENABLE(true),
		BYPASS(false),
		QOS(0),
		MEMORY(1024),

		;

		private final Class<?> valueType;
		private final Object defaultValue;

		<T> IpProperty(T defaultValue) {
			this.defaultValue = defaultValue;
			this.valueType = defaultValue.getClass();
		}

		/**
		 * @see com.slytechs.jnet.jnetruntime.util.config.NetProperty#valueType()
		 */
		@SuppressWarnings("unchecked")
		@Override
		public <T> Class<T> valueType() {
			return (Class<T>) valueType;
		}

		/**
		 * @see com.slytechs.jnet.jnetruntime.util.config.NetProperty#defaultValue()
		 */
		@SuppressWarnings("unchecked")
		@Override
		public <T> T defaultValue() {
			return (T) defaultValue;
		}

		/**
		 * @see com.slytechs.jnet.jnetruntime.util.config.NetProperty#prefix()
		 */
		@Override
		public String prefix() {
			return PREFIX;
		}
	}

	public IpConfig(NetConfig<?, ?> superconfig) {
		super(superconfig, PREFIX, IpProperty.values());
	}

	public IpConfig memory(long size, MemoryUnit unit) {
		num(IpProperty.MEMORY, size, unit);

		return this;
	}

	public IpConfig qos(long size) {
		num(IpProperty.QOS, size);

		return this;
	}
}
