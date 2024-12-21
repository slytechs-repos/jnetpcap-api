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
package com.slytechs.jnet.jnetpcap.api.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import com.slytechs.jnet.jnetpcap.api.PacketHandler.OfNative;
import com.slytechs.jnet.jnetpcap.api.internal.PostPcapPipeline.PostContext;
import com.slytechs.jnet.jnetpcap.api.processors.PostProcessors.PostProcessor;
import com.slytechs.jnet.platform.api.frame.PcapFrameHeader;
import com.slytechs.jnet.platform.api.pipeline.DataLiteral;
import com.slytechs.jnet.platform.api.pipeline.InputTransformer;
import com.slytechs.jnet.platform.api.time.TimestampUnit;
import com.slytechs.jnet.platform.api.util.MemoryUnit;
import com.slytechs.jnet.protocol.api.descriptor.PacketDissector;
import com.slytechs.jnet.protocol.api.meta.PacketFormat;
import com.slytechs.jnet.protocol.api.packet.Packet;

class InputPacketDissector
		extends InputTransformer<OfNative, PostProcessor>
		implements OfNative {

	private static final long MAX_DESCRIPTOR_SIZE = MemoryUnit.BYTES.toBytes(256);
	private final PostContext ctx;
	private final PcapFrameHeader pcapHeader;
	private MemorySegment pcapSegment;
	private ByteBuffer pcapBuffer;
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
		super(id, new DataLiteral<>(OfNative.class));

		this.ctx = ctx.clone();
		this.pcapHeader = new PcapFrameHeader(ctx.abi);
		this.dissector = ctx.dissector;

		this.descSegment = Arena.ofAuto().allocate(MAX_DESCRIPTOR_SIZE);
		this.descBuffer = descSegment.asByteBuffer();
	}

	private Packet dissectPacket(MemorySegment header, MemorySegment packet) {

		this.pcapSegment = header;
		this.pcapBuffer = header.asByteBuffer().order(ctx.abi.order());
		this.pcapHeader.bind(pcapBuffer, pcapSegment);

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
	 * @see com.slytechs.jnet.jnetpcap.api.PacketHandler.OfNative#handleNative(java.lang.foreign.MemorySegment,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public void handleNative(MemorySegment user, MemorySegment header, MemorySegment packet) {

		var goPacket = dissectPacket(header, packet);

		getOutput().postProcessPacket(goPacket, ctx);
	}

	public PostContext getContext() {
		return ctx;
	}
}