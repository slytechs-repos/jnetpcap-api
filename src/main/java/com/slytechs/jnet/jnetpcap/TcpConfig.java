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

import com.slytechs.jnet.jnetpcap.TcpConfig.TcpProperty;
import com.slytechs.jnet.jnetruntime.util.config.NetConfig;
import com.slytechs.jnet.jnetruntime.util.config.NetProperty;

/**
 * @author Mark Bednarczyk
 *
 */
public class TcpConfig extends NetConfig<TcpProperty, TcpConfig> {
	public enum TcpProperty implements NetProperty {
		NAME("tcp-config"),
		ENABLE(true),
		BYPASS(false),

		;

		private final Class<?> valueType;
		private final Object defaultValue;

		<T> TcpProperty(
				T defaultValue) {
			this.valueType = defaultValue.getClass();
			this.defaultValue = defaultValue;
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
		 * @see com.slytechs.jnet.jnetruntime.util.config.NetProperty#valueType()
		 */
		@SuppressWarnings("unchecked")
		@Override
		public Class<?> valueType() {
			return valueType;
		}

		/**
		 * @see com.slytechs.jnet.jnetruntime.util.config.NetProperty#prefix()
		 */
		@Override
		public String prefix() {
			return PREFIX;
		}
	}

	private static final String PREFIX = "protocol.tcp";

	/**
	 * @param superconfig
	 * @param prefix
	 * @param propertyTable
	 */
	public TcpConfig(NetConfig<?, ?> superconfig) {
		super(superconfig, PREFIX, TcpProperty.values());
	}

}
