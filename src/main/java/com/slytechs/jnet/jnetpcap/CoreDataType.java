/*
 * Copyright 2024 Sly Technologies Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.jnet.jnetpcap;

import java.util.function.BiFunction;
import java.util.function.Function;

import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacket;
import com.slytechs.jnet.jnetruntime.pipeline.DataType;

/**
 * PCAP specific RX processor data types.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
@SuppressWarnings("unchecked")
public enum CoreDataType implements DataType {

	/** A dissected and protocol enabled packet object type. */
	PACKET(OfPacket.class, OfPacket::wrapUser, OfPacket::wrapArray),

	/** A fully reassembled and dissected packet type. */
	REASSEMBLED_PACKET(OfPacket.class, OfPacket::wrapUser, OfPacket::wrapArray),

	;

	/** The data support. */
	private final DataSupport<?> dataSupport;

	/**
	 * Instantiates a new pcap data type.
	 *
	 * @param <T>          the generic type
	 * @param <U>          the generic type
	 * @param arrayFactory the array factory
	 * @param wrapFunction the wrap function
	 * @param arrayHandler the array handler
	 */
	<T, U> CoreDataType(Class<T> arrayFactory, BiFunction<T, U, T> wrapFunction, Function<T[], T> arrayHandler) {
		this.dataSupport = new DataSupport<T>(this, arrayFactory, arrayHandler, wrapFunction);
	}

	/**
	 * Data support.
	 *
	 * @param <T> the generic type
	 * @return the data support
	 * @see com.slytechs.jnet.jnetruntime.pipeline.DataType#dataSupport()
	 */
	@Override
	public <T> DataSupport<T> dataSupport() {
		return (DataSupport<T>) dataSupport;
	}

}
