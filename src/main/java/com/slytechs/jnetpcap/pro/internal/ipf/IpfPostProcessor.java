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

import com.slytechs.jnetpcap.pro.internal.PacketDispatcher;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public interface IpfPostProcessor extends PacketDispatcher {

	static IpfPostProcessor ipfPostProcessor(
			IpfConfig config) {

		if (isNativeIpfDispatcherSupported())
			return nativeIpfDispatcher(config);
		else
			return javaIpfDispatcher(config);
	}

	static IpfPostProcessor javaIpfDispatcher(
			IpfConfig config) {
		return new IpfPostProcessorJava(config);
	}

	static boolean isNativeIpfDispatcherSupported() {
		return IpfPostProcessorNative.isNativeSupported();
	}

	static IpfPostProcessor nativeIpfDispatcher(
			IpfConfig config) {

		return new IpfPostProcessorNative(config);
	}

}
