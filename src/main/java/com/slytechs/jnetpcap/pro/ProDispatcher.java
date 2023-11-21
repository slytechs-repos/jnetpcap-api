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

import java.lang.foreign.MemorySegment;
import java.util.Collections;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;

import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.internal.PacketDispatcher;
import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.util.PcapPacketRef;

import com.slytechs.jnetpcap.pro.internal.processor.MemorySegmentProcessors;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.descriptor.PacketDescriptor;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
class ProDispatcher extends PcapDispatcher implements PacketDispatcher {

	private Function<PacketDescriptor, Packet> packetFactory;

	private MemorySegmentProcessors memorySegmentProcessors = MemorySegmentProcessors.newInstance(Collections.emptyList());

	public ProDispatcher(MemorySegment pcapHandle, PcapHeaderABI abi, Runnable breakDispatch) {
		super(pcapHandle, abi, breakDispatch);
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.PacketReceiver#close()
	 */
	@Override
	public void close() {
		super.close();
	}

	private Packet dissectPacket(MemorySegment hdr, MemorySegment pkt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int dispatchNative(int count, NativeCallback handler, MemorySegment user) {

		return super.dispatchNative(count, memorySegmentProcessors.processAndForward(handler), user);
	}

	@Override
	public int loopNative(int count, NativeCallback handler, MemorySegment user) {
		return super.loopNative(count, handler, user);
	}

	@Override
	public PcapPacketRef next() throws PcapException {
		return super.next();
	}

	@Override
	public PcapPacketRef nextEx() throws PcapException, TimeoutException {
		return super.nextEx();
	}

}
