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

import java.util.function.BiFunction;
import java.util.function.Function;

import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacket;
import com.slytechs.jnet.jnetruntime.pipeline.DataType;
import com.slytechs.jnet.jnetruntime.pipeline.DataTypeInfo;
import com.slytechs.jnet.jnetruntime.pipeline.RawDataType;

/**
 * PCAP specific RX processor data types.
 *
 * @author Mark Bednarczyk
 */
@SuppressWarnings("unchecked")
public enum CoreDataType implements DataTypeInfo {

	/** A dissected and protocol enabled packet object type. */
	PACKET(OfPacket.class, OfPacket::wrapUser, CoreDataType::arrayOfPacket),

	/** A fully reassembled and dissected packet type. */
	REASSEMBLED_PACKET(OfPacket.class, OfPacket::wrapUser, CoreDataType::arrayOfPacket),

	;

	/** The data settingsSupport. */
	private final DataType<?> dataType;

	/**
	 * Instantiates a new pcap data type.
	 *
	 * @param <T>           the generic type
	 * @param dataClass     the array factory
	 * @param opaqueWrapper the opaque wrapper
	 * @param arrayHandler  the array handler
	 */
	<T> CoreDataType(Class<T> dataClass, BiFunction<T, ? super Object, T> opaqueWrapper,
			Function<T[], T> arrayHandler) {
		this.dataType = new RawDataType<T>(name(), dataClass, arrayHandler);
	}

	/**
	 * Data settingsSupport.
	 *
	 * @param <T> the generic type
	 * @return the data settingsSupport
	 * @see com.slytechs.jnet.jnetruntime.pipeline.DataTypeTooCompilicated#dataSupport()
	 */
	@Override
	public <T> DataType<T> dataType() {
		return (DataType<T>) dataType;
	}

	/**
	 * Wrap array.
	 *
	 * @param <U>   the generic type
	 * @param array the array
	 * @return the of packet
	 */
	static <U> OfPacket<U> arrayOfPacket(OfPacket<U>[] array) {
		return (u, p) -> {
			for (var a : array)
				a.handlePacket(u, p);
		};
	}

}
