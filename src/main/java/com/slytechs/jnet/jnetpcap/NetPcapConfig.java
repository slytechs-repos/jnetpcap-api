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

import com.slytechs.jnet.jnetpcap.NativePacketPipeline.NativePacketConfig;
import com.slytechs.jnet.jnetpcap.NetPcapConfig.NetPcapProperty;
import com.slytechs.jnet.jnetruntime.util.config.NetConfig;
import com.slytechs.jnet.jnetruntime.util.config.NetConfigurator;
import com.slytechs.jnet.jnetruntime.util.config.NetProperty;

/**
 * @author Mark Bednarczyk
 */
public class NetPcapConfig extends NetConfig<NetPcapProperty, NetPcapConfig> {
	private static final String PREFIX = "netpcap";

	public enum NetPcapProperty implements NetProperty {
		NAME("netpcap"),

		;

		private final Class<?> valueType;
		private final Object defaultValue;

		<T> NetPcapProperty(T defaultValue) {
			this.valueType = defaultValue.getClass();
			this.defaultValue = defaultValue;
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

	public NetPcapConfig(NetConfigurator configurator, NetPcap pcap) {
		super(configurator, PREFIX, NetPcapProperty.values());
	}

	public NativePacketConfig configureNative() {
		return newConfig(NativePacketConfig::new);
	}

	public IpConfig configureIp() {
		return newConfig(IpConfig::new);
	}

	public TcpConfig configureTcp() {
		return newConfig(TcpConfig::new);
	}
}
