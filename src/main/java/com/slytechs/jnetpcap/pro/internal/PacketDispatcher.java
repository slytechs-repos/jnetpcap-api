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

import com.slytechs.jnet.protocol.Frame.FrameNumber;
import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.descriptor.PacketDissector;
import com.slytechs.jnet.protocol.meta.PacketFormat;
import com.slytechs.jnetpcap.pro.PcapProHandler;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public interface PacketDispatcher extends PcapDispatcher {

	static PacketDispatcher packetDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			PacketDescriptorType descriptorType) {

		if (isNativePacketDispatcherSupported())
			return nativePacketDispatcher(pcapHandle, breakDispatch, descriptorType);
		else
			return javaPacketDispatcher(pcapHandle, breakDispatch, descriptorType);
	}

	static PacketDispatcher javaPacketDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			PacketDescriptorType descriptorType) {

		return new JavaPacketDispatcher(pcapHandle, breakDispatch, descriptorType);
	}

	static boolean isNativePacketDispatcherSupported() {
		return false;
	}

	static PacketDispatcher nativePacketDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			PacketDescriptorType descriptorType) {
		throw new UnsupportedOperationException();
	}

	void setFrameNumber(FrameNumber frameNumberAssigner);

	void setPacketFormat(PacketFormat newFormat);

	<U> int loopPacket(int count, PcapProHandler.OfPacket<U> sink, U user);

	<U> int dispatchPacket(int count, PcapProHandler.OfPacket<U> sink, U user);

	PacketDescriptorType getDescriptorType();

	PacketDissector getDissector();

	void setPortNumber(int portNo);
}
