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

import com.slytechs.jnet.jnetpcap.NativePacketPipeline.NativePacketPipe;
import com.slytechs.jnet.jnetruntime.pipeline.DataType;
import com.slytechs.jnet.jnetruntime.pipeline.DataType.DataSupport;

public enum NetDataTypes implements DataType {
	NATIVE_PACKET_PIPE(NativePacketPipe.class, NetDataTypes::arrayWrapper),

	;

	static NativePacketPipe arrayWrapper(NativePacketPipe[] array) {
		return (u, h, p) -> {
			for (var a : array)
				a.processNativePacket(u, h, p);
		};
	}

	/** The data support. */
	private final DataSupport<?> dataSupport;

	<T> NetDataTypes(Class<T> dataClass, Function<T[], T> arrayHandler) {
		this.dataSupport = new DataSupport<T>(this, dataClass, arrayHandler);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <T> DataSupport<T> dataSupport() {
		return (DataSupport<T>) dataSupport;
	}

}