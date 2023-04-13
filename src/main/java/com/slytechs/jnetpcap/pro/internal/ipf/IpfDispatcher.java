/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
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
package com.slytechs.jnetpcap.pro.internal.ipf;

import java.lang.foreign.MemoryAddress;

import com.slytechs.jnetpcap.pro.internal.PacketDispatcher;
import com.slytechs.protocol.pack.core.constants.PacketDescriptorType;
import com.slytechs.protocol.runtime.util.MemoryUnit;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public interface IpfDispatcher extends PacketDispatcher {

	static IpfDispatcher ipfDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			PacketDescriptorType descriptorType) {

		if (isNativeIpfDispatcherSupported())
			return nativeIpfDispatcher(pcapHandle, breakDispatch, descriptorType);
		else
			return javaIpfDispatcher(pcapHandle, breakDispatch, descriptorType);
	}

	static IpfDispatcher javaIpfDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			PacketDescriptorType descriptorType) {
		return new JavaIpfDispatcher(pcapHandle, breakDispatch, descriptorType);
	}

	static boolean isNativeIpfDispatcherSupported() {
		return NativeIpfDispatcher.isNativeSupported();
	}

	static IpfDispatcher nativeIpfDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			PacketDescriptorType descriptorType) {

		return new NativeIpfDispatcher(pcapHandle, breakDispatch, descriptorType);
	}

	void setIpfTableSize(int entryCount, long bufferSize, MemoryUnit unit);

}
