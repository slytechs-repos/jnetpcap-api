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

import com.slytechs.jnetpcap.pro.PacketDispatcher;

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
			IpfConfig config) {

		if (isNativeIpfDispatcherSupported())
			return nativeIpfDispatcher(pcapHandle, breakDispatch, config);
		else
			return javaIpfDispatcher(pcapHandle, breakDispatch, config);
	}

	static IpfDispatcher javaIpfDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			IpfConfig config) {
		return new JavaIpfDispatcher(pcapHandle, breakDispatch, config);
	}

	static boolean isNativeIpfDispatcherSupported() {
		return NativeIpfDispatcher.isNativeSupported();
	}

	static IpfDispatcher nativeIpfDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			IpfConfig config) {

		return new NativeIpfDispatcher(pcapHandle, breakDispatch, config);
	}

}
