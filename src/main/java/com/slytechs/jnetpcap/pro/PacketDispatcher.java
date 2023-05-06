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
package com.slytechs.jnetpcap.pro;

import java.lang.foreign.MemoryAddress;

import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnetpcap.pro.internal.JavaPacketDispatcher;
import com.slytechs.jnetpcap.pro.internal.PacketStatistics;
import com.slytechs.protocol.Frame.FrameNumber;
import com.slytechs.protocol.descriptor.PacketDissector;
import com.slytechs.protocol.meta.PacketFormat;
import com.slytechs.protocol.pack.core.constants.PacketDescriptorType;
import com.slytechs.protocol.runtime.time.TimestampUnit;

/**
 * Packet dispatcher with protocol level support.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public interface PacketDispatcher extends PcapDispatcher {

	public class PacketDispatcherConfig {

		public int portNo;
		public FrameNumber frameNo = FrameNumber.of();
		public TimestampUnit timestampUnit = TimestampUnit.PCAP_MICRO;
		public PacketFormat formatter;
		public PacketDissector dissector;
		public PacketDescriptorType descriptorType;
		public PcapHeaderABI abi;

	}

	/**
	 * Checks if is native packet dispatcher supported.
	 *
	 * @return true, if is native packet dispatcher supported
	 */
	static boolean isNativePacketDispatcherSupported() {
		return false;
	}

	/**
	 * Java packet dispatcher.
	 *
	 * @param pcapHandle     the pcap handle
	 * @param breakDispatch  the break dispatch
	 * @param descriptorType the descriptor type
	 * @return the packet dispatcher
	 */
	static PacketDispatcher javaPacketDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			PacketDispatcherConfig config) {

		return new JavaPacketDispatcher(pcapHandle, breakDispatch, config);
	}

	/**
	 * Native packet dispatcher.
	 *
	 * @param pcapHandle     the pcap handle
	 * @param breakDispatch  the break dispatch
	 * @param descriptorType the descriptor type
	 * @return the packet dispatcher
	 */
	static PacketDispatcher nativePacketDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			PacketDispatcherConfig config) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Packet dispatcher.
	 *
	 * @param pcapHandle     the pcap handle
	 * @param breakDispatch  the break dispatch
	 * @param descriptorType the descriptor type
	 * @return the packet dispatcher
	 */
	static PacketDispatcher packetDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			PacketDispatcherConfig config) {

		if (isNativePacketDispatcherSupported())
			return nativePacketDispatcher(pcapHandle, breakDispatch, config);
		else
			return javaPacketDispatcher(pcapHandle, breakDispatch, config);
	}

	/**
	 * Dispatch packet.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 */
	<U> int dispatchPacket(int count, PcapProHandler.OfPacket<U> sink, U user);

	/**
	 * Gets the dissector.
	 *
	 * @return the dissector
	 */
	PacketDissector getDissector();

	/**
	 * Gets the descriptor type.
	 *
	 * @return the descriptor type
	 */
	PacketDescriptorType getDescriptorType();

	/**
	 * Loop packet.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 */
	<U> int loopPacket(int count, PcapProHandler.OfPacket<U> sink, U user);

	PacketStatistics getPacketStatistics();
}
