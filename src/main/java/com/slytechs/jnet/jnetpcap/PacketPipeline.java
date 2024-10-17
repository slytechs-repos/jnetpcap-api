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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacket;
import com.slytechs.jnet.jnetpcap.PacketPipeline.StatefulPacket;
import com.slytechs.jnet.jnetruntime.pipeline.AbstractInput;
import com.slytechs.jnet.jnetruntime.pipeline.AbstractOutput;
import com.slytechs.jnet.jnetruntime.pipeline.AbstractPipeline;
import com.slytechs.jnet.jnetruntime.pipeline.DataTransformer.InputTransformer.EntryPoint;
import com.slytechs.jnet.jnetruntime.pipeline.DataTransformer.OutputTransformer.EndPoint;
import com.slytechs.jnet.jnetruntime.pipeline.HeadNode;
import com.slytechs.jnet.jnetruntime.pipeline.TailNode;
import com.slytechs.jnet.jnetruntime.time.TimestampUnit;
import com.slytechs.jnet.protocol.Frame.FrameNumber;
import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.descriptor.PacketDescriptor;
import com.slytechs.jnet.protocol.descriptor.PacketDissector;
import com.slytechs.jnet.protocol.meta.PacketFormat;

/**
 * @author Mark Bednarczyk
 */
public class PacketPipeline extends AbstractPipeline<StatefulPacket, PacketPipeline> {

	private class PacketDissectorInput
			extends AbstractInput<NativeCallback, StatefulPacket, PacketDissectorInput>
			implements NativeCallback {

		public static class DissectorContext {
			/** The Constant DESC_BUFFER_SIZE. */
			private static final int DESC_BUFFER_SIZE = 1024;

			/** The port no. */
			public int portNo;

			/** The port name. */
			public String portName = "";

			/** The frame no. */
			public FrameNumber frameNo = FrameNumber.of();

			/** The timestamp unit. */
			public TimestampUnit timestampUnit = TimestampUnit.PCAP_MICRO;
			/** The formatter. */
			public PacketFormat formatter = new PacketFormat();

			/** The descriptor type. */
			public PacketDescriptorType descriptorType;

			/** The dissector. */
			public PacketDissector dissector;

			/** The abi. */
			public PcapHeaderABI abi;

			/** The singleton desc buffer. */
			private ByteBuffer reusableDescBuffer;

			/** The singleton packet. */
			private final Packet reusablePacket;

			public DissectorContext() {
				this(PacketDescriptorType.TYPE2);
			}

			public DissectorContext(PacketDescriptorType type) {
				this.descriptorType = type;
				this.dissector = PacketDissector.dissector(type);

				this.reusableDescBuffer = ByteBuffer
						.allocateDirect(DissectorContext.DESC_BUFFER_SIZE)
						.order(ByteOrder.nativeOrder());

				this.reusablePacket = new Packet(descriptorType.newDescriptor());
			}
		}

		private DissectorContext dissectorCtx = new DissectorContext();

		public PacketDissectorInput(
				HeadNode<StatefulPacket> headNode) {
			super(headNode, "PacketDissector", PcapDataType.PCAP_NATIVE_PACKET, NetDataTypes.STATEFUL_PACKET);
		}

		protected Packet createSingletonPacket(ByteBuffer buf, MemorySegment data,
				int caplen, int wirelen, long timestamp) {

			dissectorCtx.dissector.dissectPacket(buf, timestamp, caplen, wirelen);
			dissectorCtx.dissector.writeDescriptor(dissectorCtx.reusableDescBuffer.clear());
			dissectorCtx.dissector.reset();

			Packet packet = dissectorCtx.reusablePacket;
			PacketDescriptor desc = packet.descriptor();

			packet.bind(buf.flip(), data);
			desc.bind(dissectorCtx.reusableDescBuffer.flip());

			desc.portNo(dissectorCtx.portNo);
			desc.portName(dissectorCtx.portName);
			desc.frameNo(dissectorCtx.frameNo.getUsing(timestamp, dissectorCtx.portNo));
			desc.timestampUnit(dissectorCtx.timestampUnit);
			packet.setFormatter(dissectorCtx.formatter);
			desc.timestampUnit(dissectorCtx.timestampUnit);

			return packet;
		}

		/**
		 * @see org.jnetpcap.PcapHandler.NativeCallback#nativeCallback(java.lang.foreign.MemorySegment,
		 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
		 */
		@Override
		public void nativeCallback(MemorySegment user, MemorySegment header, MemorySegment data) {
			if (super.isEmpty())
				return;

			ByteBuffer dataBuf = data.asByteBuffer();
			final var abi = dissectorCtx.abi;

			int caplen = abi.captureLength(header);
			int wirelen = abi.wireLength(header);
			long tvSec = abi.tvSec(header);
			long tvUsec = abi.tvUsec(header);
			long timestamp = dissectorCtx.timestampUnit.ofSecond(tvSec, tvUsec);

			var packet = createSingletonPacket(dataBuf, data, caplen, wirelen, timestamp);

			outputData().handlePacket(packet, pipelineCtx);
		}
	}

	public static class PacketOutput
			extends AbstractOutput<StatefulPacket, NetPcapHandler.OfPacket<Object>, PacketOutput>
			implements StatefulPacket {

		/**
		 * @param tailNode
		 * @param name
		 * @param inputType
		 * @param outputType
		 */
		public PacketOutput(TailNode<StatefulPacket> tailNode) {
			super(tailNode, "PacketOutput", NetDataTypes.STATEFUL_PACKET, NetDataTypes.OF_PACKET);
		}

		/**
		 * @see com.slytechs.jnet.jnetpcap.PacketPipeline.StatefulPacket#handlePacket(com.slytechs.jnet.protocol.Packet,
		 *      com.slytechs.jnet.jnetpcap.PacketPipeline.PacketPipelineContext)
		 */
		@Override
		public void handlePacket(Packet packet, PacketPipelineContext ctx) {
			outputData().handlePacket(userOpaque(), packet);
		}

	}

	public static class PacketPipelineContext {

	}

	public interface StatefulPacket {
		void handlePacket(Packet packet, PacketPipelineContext ctx);
	}

	private final PacketPipelineContext pipelineCtx = new PacketPipelineContext();
	private final PacketDissectorInput input;
	private final PacketOutput output;
	private final EntryPoint<NativeCallback> entryPointOfNative;
	private EndPoint<OfPacket<?>> endPointOfPacket;

	/**
	 * @param name
	 * @param dataType
	 */
	public PacketPipeline(String name, PcapHeaderABI abi) {
		super(name, NetDataTypes.STATEFUL_PACKET);

		this.input = this.addInput(PacketDissectorInput::new);
		this.input.dissectorCtx.portName = name;
		this.input.dissectorCtx.abi = abi;

		this.entryPointOfNative = input.createEntryPoint(name());

		output = this.addOutput(PacketOutput::new);
	}

	private PacketDissectorInput.DissectorContext ctx() {
		return input.dissectorCtx;
	}

	@SuppressWarnings({ "rawtypes",
			"unchecked" })
	public EndPoint<OfPacket<?>> endPointOfPacket() {
		if (endPointOfPacket == null)
			this.endPointOfPacket = (EndPoint) output
					.createMutableEndPoint("user-endpoint")
					.resetAsEmpty();

		return endPointOfPacket;
	}

	/**
	 * @return
	 */
	public EntryPoint<NativeCallback> entryPoint() {
		return entryPointOfNative;
	}

	public PacketPipeline port(int portNo) {
		ctx().portNo = portNo;

		return this;
	}

}
