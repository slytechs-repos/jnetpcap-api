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

import org.jnetpcap.internal.PacketDispatcher;

import com.slytechs.jnetpcap.pro.PcapPro.PcapProContext;
import com.slytechs.jnetpcap.pro.internal.PacketReceiver;
import com.slytechs.jnetpcap.pro.processor.IpfReassembler;

/**
 * The Interface IpfDispatcher.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public interface IpfDispatcher extends PacketReceiver {

	/**
	 * New instance.
	 *
	 * @param pcap    the pcap
	 * @param packet  the packet
	 * @param config  the config
	 * @param context the context
	 * @return the ipf dispatcher
	 */
	static IpfDispatcher newInstance(
			PacketDispatcher pcap,
			PacketReceiver packet,
			IpfReassembler config,
			PcapProContext context) {

		if (isNativeSupported())
			return newNativeInstance(pcap, packet, config, context);
		else
			return newJavaInstance(pcap, packet, config, context);
	}

	/**
	 * New java instance.
	 *
	 * @param pcap    the pcap
	 * @param packet  the packet
	 * @param config  the config
	 * @param context the context
	 * @return the ipf dispatcher
	 */
	static IpfDispatcher newJavaInstance(
			PacketDispatcher pcap,
			PacketReceiver packet,
			IpfReassembler config,
			PcapProContext context) {
		return new JavaIpfDispatcher(pcap, packet, config, context);
	}

	/**
	 * Checks if is native supported.
	 *
	 * @return true, if is native supported
	 */
	static boolean isNativeSupported() {
		return IpfDispatcherNative.isNativeSupported();
	}

	/**
	 * New native instance.
	 *
	 * @param pcap    the pcap
	 * @param packet  the packet
	 * @param config  the config
	 * @param context the context
	 * @return the ipf dispatcher
	 */
	static IpfDispatcher newNativeInstance(
			PacketDispatcher pcap,
			PacketReceiver packet,
			IpfReassembler config,
			PcapProContext context) {

		return new IpfDispatcherNative(pcap, packet, config, context);
	}

}
