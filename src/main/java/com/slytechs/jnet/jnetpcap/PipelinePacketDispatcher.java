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

import java.lang.foreign.MemorySegment;
import java.util.function.Supplier;

import com.slytechs.jnet.jnetpcap.PacketHandler.OfArray;
import com.slytechs.jnet.jnetpcap.PacketHandler.OfBuffer;
import com.slytechs.jnet.jnetpcap.PacketHandler.OfForeign;
import com.slytechs.jnet.jnetpcap.PacketHandler.OfNative;
import com.slytechs.jnet.jnetpcap.PacketHandler.OfPacket;
import com.slytechs.jnet.jnetpcap.internal.PostPcapPipeline;
import com.slytechs.jnet.jnetpcap.internal.PrePcapPipeline;
import com.slytechs.jnet.jnetruntime.time.TimestampUnit;
import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.meta.PacketFormat;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
class PipelinePacketDispatcher implements PacketDispatcher {

	private final Packet defaultPacket = new Packet(PacketDescriptorType.TYPE2);

	private final PrePcapPipeline prePipeline;
	private final PostPcapPipeline postPipeline;

	public PipelinePacketDispatcher(PrePcapPipeline prePipeline, PostPcapPipeline postPipeline) {
		this.prePipeline = prePipeline;
		this.postPipeline = postPipeline;

		defaultPacket.descriptor().timestampUnit(TimestampUnit.EPOCH_MICRO);
		defaultPacket.setFormatter(new PacketFormat());
	}

	@Override
	public boolean nextPacket(Packet packet) {
		return prePipeline.nextPacket(packet);
	}

	@Override
	public int dispatchNative(int count, OfNative handler, MemorySegment user) {
		return prePipeline.dispatchNative(count, handler, user);
	}

	@Override
	public <U> int dispatchForeign(int count, OfForeign<U> handler, U user) {
		return prePipeline.dispatchForeign(count, handler, user);
	}

	@Override
	public <U> int dispatchBuffer(int count, OfBuffer<U> handler, U user) {
		return prePipeline.dispatchBuffer(count, handler, user);
	}

	@Override
	public <U> int dispatchArray(int count, OfArray<U> handler, U user) {
		return prePipeline.dispatchArray(count, handler, user);
	}

	@Override
	public Packet getDefaultPacket() {
		return defaultPacket;
	}

	@Override
	public <U> int dispatchPacket(int count, OfPacket<U> handler, U user, Supplier<Packet> packetFactory) {
		return postPipeline.dispatchPacket(count, handler, user, packetFactory);
	}

	@Override
	public long capturePackets(long count) {
		return prePipeline.capturePackets(count);
	}

	@Override
	public <U> int dispatchPacket(int count, OfPacket<U> handler, U user) {
		return postPipeline.dispatchPacket(count, handler, user);
	}
}
