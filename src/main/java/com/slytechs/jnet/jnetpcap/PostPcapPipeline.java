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
import java.util.function.BiFunction;
import java.util.function.Supplier;

import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnet.jnetpcap.PacketHandler.OfNative;
import com.slytechs.jnet.jnetpcap.PacketHandler.OfPacket;
import com.slytechs.jnet.jnetpcap.PostProcessors.PostProcessorData;
import com.slytechs.jnet.jnetruntime.pipeline.DT;
import com.slytechs.jnet.jnetruntime.pipeline.OutputStack;
import com.slytechs.jnet.jnetruntime.pipeline.OutputTransformer;
import com.slytechs.jnet.jnetruntime.pipeline.Pipeline;
import com.slytechs.jnet.jnetruntime.pipeline.RawDataType;
import com.slytechs.jnet.jnetruntime.time.TimestampUnit;
import com.slytechs.jnet.jnetruntime.util.Registration;
import com.slytechs.jnet.protocol.Frame.FrameNumber;
import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.descriptor.PacketDissector;
import com.slytechs.jnet.protocol.meta.PacketFormat;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
class PostPcapPipeline
		extends Pipeline<PostProcessorData>
		implements PostProcessors, Registration {

	public static final String NAME = "PostPcapPipeline";

	public static class PostContext implements Cloneable {

		/**
		 * @param abi2
		 */
		public PostContext(PcapHeaderABI abi, Supplier<Packet> defaultPacketFactory) {
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
		public final PcapHeaderABI abi;

		/** The singleton desc buffer. */
		private ByteBuffer reusableDescBuffer;

		public final Supplier<Packet> defaultPacketFactory;
		public Supplier<Packet> packetFactory;

		public final MemorySegment descriptorSegment = Arena.ofAuto().allocate(1024);
		public final ByteBuffer descriptorBuffer = descriptorSegment.asByteBuffer();

		@SuppressWarnings("exports")
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

	private final OutputStack<PostProcessorData> cbStack;
	private final OutputTransformer<PostProcessorData, OfPacket<Object>> packetOutput;

	/**
	 * @param name
	 * @param dataType
	 */
	public PostPcapPipeline(BiFunction<Object, OfNative, Registration> connectionPoint,
			PacketDispatcherSource source,
			PcapHeaderABI abi) {
		super(NAME, new RawDataType<>(PostProcessorData.class));
		this.dispatcherSource = source;

		var defaultContext = new PostContext(abi, source::getDefaultPacket);
		defaultContext.packetFactory = source::getDefaultPacket;

		var descriptorType = defaultContext.defaultPacketFactory.get().descriptor().type();
		defaultContext.dissector = PacketDissector.dissector(descriptorType);

		this.input = new InputPacketDissector("PreProcessors", defaultContext);
		head().addInput(input).getInputPerma();

		this.cbStack = tail().getOutputStack();
		this.packetOutput = cbStack.createTransformer("OfPacket", this::outputOfPacket, new DT<OfPacket<Object>>() {});

		this.upstreamRegistration = connectionPoint.apply("PostProcessors", input);
	}

	private final PostProcessorData outputOfPacket(Supplier<OfPacket<Object>> out) {
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
	public <U> int dispatchPacket(int count, OfPacket<U> handler, U user, Supplier<Packet> packetFactory) {

		input.getContext().user = user;
		input.getContext().packetFactory = packetFactory;

		packetOutput.connectNoRegistration((OfPacket<Object>) handler);
		cbStack.push(packetOutput);

		dispatcherSource.captureFromSource(count);

		cbStack.pop();
		packetOutput.disconnect();

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
	public <U> int dispatchPacket(int count, OfPacket<U> handler, U user) {
		input.getContext().user = user;
		input.getContext().packetFactory = input.getContext().defaultPacketFactory;

		packetOutput.connectNoRegistration((OfPacket<Object>) handler);
		cbStack.push(packetOutput);

		dispatcherSource.captureFromSource(count);

		cbStack.pop();
		packetOutput.disconnect();

		return 1;
	}
}
