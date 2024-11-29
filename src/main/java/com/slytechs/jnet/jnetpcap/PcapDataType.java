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

import java.util.function.Function;

import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.PcapHandler.OfByteBuffer;

import com.slytechs.jnet.jnetruntime.pipeline.DataType;

/**
 * PCAP specific RX processor data types.
 *
 * @author Mark Bednarczyk
 */
@SuppressWarnings("unchecked")
public enum PcapDataType implements DataType {

	/** Low level PCAP callback type. */
	PCAP_NATIVE_PACKET(NativeCallback.class, PcapDataType::arrayOfNativeCallbacks),

	/** Raw PCAP packet in form of memory segments. */
	PCAP_RAW_PACKET(OfByteBuffer.class, PcapDataType::arrayOfByteBuffers),

	;

	/** The data settingsSupport. */
	private final DataSupport<?> dataSupport;

	/**
	 * Instantiates a new pcap data type.
	 *
	 * @param <T>          the generic type
	 * @param <U>          the generic type
	 * @param dataClass    the array factory
	 * @param arrayHandler the array handler
	 */
	<T> PcapDataType(
			Class<T> dataClass,
			Function<T[], T> arrayHandler) {
		this.dataSupport = new DataSupport<T>(this, dataClass, arrayHandler);
	}

	/**
	 * Data settingsSupport.
	 *
	 * @param <T> the generic type
	 * @return the data settingsSupport
	 * @see com.slytechs.jnet.jnetruntime.pipeline.DataType#dataSupport()
	 */
	@Override
	public <T> DataSupport<T> dataSupport() {
		return (DataSupport<T>) dataSupport;
	}

	/**
	 * Wrap array.
	 *
	 * @param array the array
	 * @return the native callback
	 */
	static NativeCallback arrayOfNativeCallbacks(NativeCallback[] array) {
		return (u, h, p) -> {
			for (var a : array)
				a.nativeCallback(u, h, p);
		};
	}

	/**
	 * Wrap array.
	 *
	 * @param <U>   the generic type
	 * @param array the array
	 * @return the of memory segment
	 */
	static <U> OfByteBuffer<U> arrayOfByteBuffers(OfByteBuffer<U>[] array) {
		return (u, h, p) -> {
			for (var a : array)
				a.handleByteBuffer(u, h, p);
		};
	}

}
