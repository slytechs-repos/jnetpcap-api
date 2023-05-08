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

import org.jnetpcap.internal.PcapDispatcher;

import com.slytechs.jnetpcap.pro.IpfReassembler;
import com.slytechs.jnetpcap.pro.internal.PacketDispatcher;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public interface IpfDispatcher extends PacketDispatcher {

	static IpfDispatcher newInstance(
			PcapDispatcher pcap,
			PacketDispatcher packet,
			IpfReassembler config) {

		if (isNativeSupported())
			return newNativeInstance(pcap, packet, config);
		else
			return newJavaInstance(pcap, packet, config);
	}

	static IpfDispatcher newJavaInstance(
			PcapDispatcher pcap,
			PacketDispatcher packet,
			IpfReassembler config) {
		return new JavaIpfDispatcher(pcap, packet, config);
	}

	static boolean isNativeSupported() {
		return IpfDispatcherNative.isNativeSupported();
	}

	static IpfDispatcher newNativeInstance(
			PcapDispatcher pcap,
			PacketDispatcher packet,
			IpfReassembler config) {

		return new IpfDispatcherNative(pcap, packet, config);
	}

}
