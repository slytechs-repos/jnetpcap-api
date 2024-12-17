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
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnet.jnetpcap.PacketHandler.OfNative;
import com.slytechs.jnet.jnetpcap.PacketHandler.OfPacket;
import com.slytechs.jnet.jnetpcap.PostProcessors.PostData;
import com.slytechs.jnet.jnetruntime.pipeline.DT;
import com.slytechs.jnet.jnetruntime.pipeline.OutputSwitch;
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
		extends Pipeline<PostData>
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

	private final OutputSwitch<PostData> cbSwitch;
	private final Registration upstreamRegistration;

	@SuppressWarnings("rawtypes")
	private final Consumer<OfPacket> packetConnector;
	private final PacketDispatcher dispatcher;
	private final InputPacketDissector input;

	/**
	 * @param name
	 * @param dataType
	 */
	@SuppressWarnings("unchecked")
	public PostPcapPipeline(BiFunction<Object, OfNative, Registration> connectionPoint, PacketDispatcher dispatcher,
			PcapHeaderABI abi) {
		super(NAME, new RawDataType<>(PostData.class));
		this.dispatcher = dispatcher;

		var defaultContext = new PostContext(abi, dispatcher::getDefaultPacket);
		defaultContext.packetFactory = dispatcher::getDefaultPacket;

		var descriptorType = defaultContext.defaultPacketFactory.get().descriptor().type();
		defaultContext.dissector = PacketDissector.dissector(descriptorType);

		this.input = new InputPacketDissector("OfNative", defaultContext);
		head().addInput(input).getInputPerma();

		/* Only 1 of the switch outputs can be selected at a time */
		this.cbSwitch = tail().getOutputSwitch();
		this.cbSwitch.setOutput(0, this::outputOfPacket, new DT<OfPacket<Object>>() {});

		this.upstreamRegistration = connectionPoint.apply("mainOutput", input);

		var out1 = tail().addOutput(0, "OfPacket", this::outputOfPacket,
				new DT<PacketHandler.OfPacket<Object>>() {});
		this.packetConnector = cb -> out1.connect(cb);

	}

	private final PostData outputOfPacket(Supplier<OfPacket<Object>> out) {
		return (Packet packet, PostContext postContext) -> out.get().handlePacket(postContext.user, packet);
	}

	/**
	 * @see com.slytechs.jnet.jnetruntime.util.Registration#unregister()
	 */
	@Override
	public void unregister() {
		upstreamRegistration.unregister();
	}

	private <U> void switchToPacketCallback(OfPacket<U> cb, U user, Supplier<Packet> packetFactory) {
		cbSwitch.select(0);
		input.getContext().user = user;
		input.getContext().packetFactory = packetFactory;

		packetConnector.accept(cb);
	}

	public <U> int dispatchPacket(int count, OfPacket<U> cb, U user, Supplier<Packet> packetFactory) {
		this.switchToPacketCallback(cb, user, packetFactory);

		dispatcher.capturePackets(count);

		cbSwitch.reset();

		return 1;
	}

	/**
	 * @param <U>
	 * @param count
	 * @param cb
	 * @param user
	 * @return
	 */
	public <U> int dispatchPacket(int count, OfPacket<U> cb, U user) {
		this.switchToPacketCallback(cb, user, input.getContext().defaultPacketFactory);

		dispatcher.capturePackets(count);

		cbSwitch.reset();

		return 1;
	}
}
