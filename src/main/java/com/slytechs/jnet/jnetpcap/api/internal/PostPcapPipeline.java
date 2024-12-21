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
import java.util.function.Supplier;

import com.slytechs.jnet.jnetpcap.api.PacketDispatcherSource;
import com.slytechs.jnet.jnetpcap.api.PacketHandler.OfNative;
import com.slytechs.jnet.jnetpcap.api.PacketHandler.OfPacket;
import com.slytechs.jnet.jnetpcap.api.processors.PostProcessors;
import com.slytechs.jnet.jnetpcap.api.processors.PostProcessors.PostProcessor;
import com.slytechs.jnet.platform.api.frame.FrameABI;
import com.slytechs.jnet.platform.api.pipeline.DataLiteral;
import com.slytechs.jnet.platform.api.pipeline.OutputConnector;
import com.slytechs.jnet.platform.api.pipeline.OutputStack;
import com.slytechs.jnet.platform.api.pipeline.OutputTransformer;
import com.slytechs.jnet.platform.api.pipeline.Pipeline;
import com.slytechs.jnet.platform.api.time.TimestampUnit;
import com.slytechs.jnet.platform.api.util.Registration;
import com.slytechs.jnet.protocol.api.common.Frame.FrameNumber;
import com.slytechs.jnet.protocol.api.descriptor.PacketDissector;
import com.slytechs.jnet.protocol.api.meta.PacketFormat;
import com.slytechs.jnet.protocol.api.packet.Packet;
import com.slytechs.jnet.protocol.tcpip.constants.PacketDescriptorType;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class PostPcapPipeline
		extends Pipeline<PostProcessor>
		implements PostProcessors, Registration {

	public static final String NAME = "PostPcapPipeline";

	public static class PostContext implements Cloneable {

		/**
		 * @param abi2
		 */
		public PostContext(FrameABI abi, Supplier<Packet> defaultPacketFactory) {
			this.abi = abi;
			this.defaultPacketFactory = defaultPacketFactory;
		}

		public Object user;

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
		public final FrameABI abi;

		/** The singleton desc buffer. */
		private ByteBuffer reusableDescBuffer;

		public final Supplier<Packet> defaultPacketFactory;
		public Supplier<Packet> packetFactory;

		public final MemorySegment descriptorSegment = Arena.ofAuto().allocate(1024);
		public final ByteBuffer descriptorBuffer = descriptorSegment.asByteBuffer();

		@Override
		public PostContext clone() {
			try {
				return (PostContext) super.clone();
			} catch (CloneNotSupportedException e) {
				throw new IllegalStateException(e);
			}
		}

	}

	private final Registration upstreamRegistration;

	private final PacketDispatcherSource dispatcherSource;
	private final InputPacketDissector input;

	private final OutputStack<PostProcessor> outputStack;
	private final OutputTransformer<PostProcessor, OfPacket<Object>> packetOutput;

	/**
	 * @param name
	 * @param dataType
	 */
	public PostPcapPipeline(
			OutputConnector<OfNative> connectionPoint,
			PacketDispatcherSource source,
			FrameABI abi) {
		super(NAME, new DataLiteral<>(PostProcessor.class));

		this.dispatcherSource = source;

		var defaultContext = new PostContext(abi, source::getDefaultPacket);
		defaultContext.packetFactory = source::getDefaultPacket;

		var descriptorType = defaultContext.defaultPacketFactory.get().descriptor().type();
		defaultContext.dissector = PacketDissector.dissector(descriptorType);

		this.input = new InputPacketDissector("PreProcessors", defaultContext);
		head().addInput(input);

		this.outputStack = tail().getOutputStack();
		this.packetOutput = outputStack.createTransformer("OfPacket", this::outputOfPacket,
				new DataLiteral<OfPacket<Object>>() {});

		this.upstreamRegistration = connectionPoint.connectToOutput("PostProcessors", input);
	}

	private final PostProcessor outputOfPacket(Supplier<OfPacket<Object>> out) {
		return (Packet packet, PostContext postContext) -> out.get().handlePacket(postContext.user, packet);
	}

	/**
	 * @see com.slytechs.jnet.jnetruntime.util.Registration#unregister()
	 */
	@Override
	public void unregister() {
		upstreamRegistration.unregister();
	}

	@SuppressWarnings("unchecked")
	public <U> long dispatchPacket(long count, OfPacket<U> handler, U user, Supplier<Packet> packetFactory) {

		input.getContext().user = user;
		input.getContext().packetFactory = packetFactory;

		try (var _ = packetOutput.connect((OfPacket<Object>) handler);
				var _ = outputStack.push(packetOutput)) {

			dispatcherSource.captureFromSource(count);
		}

		return 1;
	}

	/**
	 * @param <U>
	 * @param count
	 * @param cb
	 * @param user
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public <U> long dispatchPacket(long count, OfPacket<U> handler, U user) {
		input.getContext().user = user;
		input.getContext().packetFactory = input.getContext().defaultPacketFactory;

		try (var _ = packetOutput.connect((OfPacket<Object>) handler);
				var _ = outputStack.push(packetOutput)) {

			dispatcherSource.captureFromSource(count);
		}

		return 1;
	}
}
