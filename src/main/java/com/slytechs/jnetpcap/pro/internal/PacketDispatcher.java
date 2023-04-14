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
package com.slytechs.jnetpcap.pro.internal;

import java.lang.foreign.MemoryAddress;

import org.jnetpcap.internal.PcapDispatcher;

import com.slytechs.jnetpcap.pro.PcapProHandler;
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
			PacketDescriptorType descriptorType) {

		return new JavaPacketDispatcher(pcapHandle, breakDispatch, descriptorType);
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
			PacketDescriptorType descriptorType) {
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
			PacketDescriptorType descriptorType) {

		if (isNativePacketDispatcherSupported())
			return nativePacketDispatcher(pcapHandle, breakDispatch, descriptorType);
		else
			return javaPacketDispatcher(pcapHandle, breakDispatch, descriptorType);
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
	 * Gets the descriptor type.
	 *
	 * @return the descriptor type
	 */
	PacketDescriptorType getDescriptorType();

	/**
	 * Gets the dissector.
	 *
	 * @return the dissector
	 */
	PacketDissector getDissector();

	/**
	 * Number of bytes that were dropped due to errors while receiving packets. If
	 * byte count for any packet received and dropped is not available, the counter
	 * will not reflect that correct value.
	 * 
	 * @return 64-bit counter
	 */
	long getDroppedCaplenCount();

	/**
	 * Number of packets that have been dropped due to errors when receiving
	 * packets.
	 * 
	 * @return 64-bit counter
	 */
	long getDroppedPacketCount();

	/**
	 * Number of bytes seen on the wire that were dropped due to errors while
	 * receiving packets. If byte count for any packet seen on wire and dropped is
	 * not available, the counter will not reflect that correct value.
	 * 
	 * @return 64-bit counter
	 */
	long getDroppedWirelenCount();

	/**
	 * Number of total bytes received since the start of the pcap capture.
	 * 
	 * @return a 64-bit counter in units of bytes
	 */
	long getReceivedCaplenCount();

	/**
	 * Number of packets received since that start of the pcap capture.
	 * 
	 * @return a 64-bit counter
	 */
	long getReceivedPacketCount();

	/**
	 * Number of total bytes seen on the wire since the start of the pcap capture.
	 * 
	 * @return a 64-bit counter in units of bytes
	 */
	long getReceivedWirelenCount();

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

	/**
	 * Sets the frame number.
	 *
	 * @param frameNumberAssigner the new frame number
	 */
	void setFrameNumber(FrameNumber frameNumberAssigner);

	/**
	 * Sets the packet format.
	 *
	 * @param newFormat the new packet format
	 */
	void setPacketFormat(PacketFormat newFormat);

	/**
	 * Sets the port number.
	 *
	 * @param portNo the new port number
	 */
	void setPortNumber(int portNo);

	/**
	 * @param unit
	 */
	void setTimestampUnit(TimestampUnit unit);
}
