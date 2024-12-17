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

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.PcapHeader;

import com.slytechs.jnet.jnetpcap.PacketHandler.OfNative;
import com.slytechs.jnet.jnetpcap.PostPcapPipeline.PostContext;
import com.slytechs.jnet.jnetpcap.PostProcessors.PostProcessorData;
import com.slytechs.jnet.jnetruntime.pipeline.InputTransformer;
import com.slytechs.jnet.jnetruntime.pipeline.RawDataType;
import com.slytechs.jnet.jnetruntime.time.TimestampUnit;
import com.slytechs.jnet.jnetruntime.util.MemoryUnit;
import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.descriptor.PacketDissector;
import com.slytechs.jnet.protocol.meta.PacketFormat;

class InputPacketDissector
		extends InputTransformer<OfNative, PostProcessorData>
		implements OfNative {

	private static final long MAX_DESCRIPTOR_SIZE = MemoryUnit.BYTES.toBytes(256);
	private final PostContext ctx;
	private final PcapHeader pcapHeader;
	private final MemorySegment pcapSegment;
	private final ByteBuffer pcapBuffer;
	private final PacketDissector dissector;
	private final MemorySegment descSegment;
	private final ByteBuffer descBuffer;
	private final PacketFormat packetFormat = new PacketFormat();
	private final TimestampUnit timestampUnit = TimestampUnit.EPOCH_MICRO;

	/**
	 * @param id
	 * @param dataType
	 */
	protected InputPacketDissector(Object id, PostContext ctx) {
		super(id, new RawDataType<>(OfNative.class));

		this.ctx = ctx.clone();
		this.pcapHeader = new PcapHeader(ctx.abi);
		this.pcapSegment = pcapHeader.asMemoryReference();
		this.pcapBuffer = pcapSegment.asByteBuffer();
		this.dissector = ctx.dissector;

		this.descSegment = Arena.ofAuto().allocate(MAX_DESCRIPTOR_SIZE);
		this.descBuffer = descSegment.asByteBuffer();
	}

	private Packet dissectPacket(MemorySegment header, MemorySegment packet) {
		pcapSegment.copyFrom(header);
		pcapBuffer.clear();
		pcapBuffer.order(ctx.abi.order());

		Packet goPacket = ctx.packetFactory.get();
		goPacket.setFormatter(ctx.formatter);

		ByteBuffer goBuffer = packet.asByteBuffer().order(ByteOrder.BIG_ENDIAN);
		MemorySegment goSegment = packet;
		goPacket.bind(goBuffer, goSegment);

		// timestamp 1734391539695129 [0x6296b7f9ffe19]
		long timestamp = pcapHeader.timestamp();
		int caplen = pcapHeader.captureLength();
		int wirelen = pcapHeader.wireLength();

		var desc = goPacket.descriptor();
		desc.bind(descBuffer.clear(), descSegment);

		dissector.dissectPacket(goBuffer, timestamp, caplen, wirelen);
		dissector.writeDescriptor(descBuffer);

		return goPacket;
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.PacketHandler.OfNative#handleNative(java.lang.foreign.MemorySegment,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public void handleNative(MemorySegment user, MemorySegment header, MemorySegment packet) {
		
		var goPacket = dissectPacket(header, packet);

		getOutput().processDissectedPacket(goPacket, ctx);
	}

	public PostContext getContext() {
		return ctx;
	}
}