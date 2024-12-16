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
import java.lang.foreign.ValueLayout;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.PcapHandler.OfArray;
import org.jnetpcap.PcapHandler.OfByteBuffer;
import org.jnetpcap.PcapHandler.OfMemorySegment;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnet.jnetpcap.PreProcessors.NativePacketProcessor;
import com.slytechs.jnet.jnetruntime.pipeline.DT;
import com.slytechs.jnet.jnetruntime.pipeline.InputTransformer;
import com.slytechs.jnet.jnetruntime.pipeline.OutputSwitch;
import com.slytechs.jnet.jnetruntime.pipeline.OutputTransformer;
import com.slytechs.jnet.jnetruntime.pipeline.Pipeline;
import com.slytechs.jnet.jnetruntime.pipeline.RawDataType;
import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.descriptor.PcapDescriptor;

/**
 * @author Mark Bednarczyk
 */
final class NativePacketPipeline
		extends Pipeline<NativePacketProcessor>
		implements PreProcessors {

	/**
	 * @author Mark Bednarczyk [mark@slytechs.com]
	 * @author Sly Technologies Inc.
	 */
	static class NativeContext {
		public Object user;
		public int packetCount;

		public void reset() {
			this.packetCount = 0;
			this.user = null;
		}
	}

	private final NativeCallback inputNativeCallback;
	private final NativeContext ctx = new NativeContext();

	private final OutputSwitch<NativePacketProcessor> cbSwitch;
	private final Consumer<NativeCallback> cbSwitchNativeCallback;
	@SuppressWarnings("rawtypes")
	private final Consumer<OfByteBuffer> cbSwitchOfByteBuffer;
	@SuppressWarnings("rawtypes")
	private final Consumer<OfArray> cbSwitchOfArray;
	@SuppressWarnings("rawtypes")
	private final Consumer<OfMemorySegment> cbSwitchOfMemorySegment;

	private final int NATIVE_CB = 0;
	private final int BUFFER_CB = 1;
	private final int ARRAY_CB = 2;
	private final int MEMORY_SEGMENT_CB = 3;
	private final NetPcap pcap;
	private final PcapDescriptor pcapDescriptorReusable = new PcapDescriptor();
	private final PcapHeaderABI PCAP_ABI;

	/**
	 * @param name
	 * @param reducer
	 */
	@SuppressWarnings("unchecked")
	public NativePacketPipeline(String deviceName, NetPcap pcap) {
		super(deviceName, new RawDataType<>(NativePacketProcessor.class));
		this.pcap = pcap;
		this.PCAP_ABI = pcap.getPcapHeaderABI();

		var mseg = Arena.ofAuto().allocate(PcapDescriptor.PCAP_DESCRIPTOR_LENGTH);
		this.pcapDescriptorReusable.bind(mseg.asByteBuffer(), mseg);

		this.inputNativeCallback = head()
				.addInput("NativeCallback", this::inputNativeCallback, new RawDataType<>(NativeCallback.class))
				.getInputPerma(); // Guaranteed it will never change

		/* Only 1 of the switch outputs can be selected at a time */
		this.cbSwitch = tail().getOutputSwitch();

		var out1 = cbSwitch
				.setOutput(NATIVE_CB, this::outputNativeCallback, new RawDataType<>(NativeCallback.class));
		this.cbSwitchNativeCallback = cb -> out1.connect(cb);

		var out2 = cbSwitch
				.setOutput(BUFFER_CB, this::outputOfByteBuffer, new DT<OfByteBuffer<Object>>() {});
		this.cbSwitchOfByteBuffer = cb -> out2.connect(cb);

		var out3 = cbSwitch
				.setOutput(ARRAY_CB, this::outputOfArray, new DT<OfArray<Object>>() {});
		this.cbSwitchOfArray = cb -> out3.connect(cb);

		var out4 = cbSwitch
				.setOutput(MEMORY_SEGMENT_CB, this::outputOfMemorySegment, new DT<OfMemorySegment<Object>>() {});
		this.cbSwitchOfMemorySegment = cb -> out4.connect(cb);
	}

	private final NativePacketProcessor outputOfMemorySegment(Supplier<OfMemorySegment<Object>> out) {
		return (header, packet, ctx) -> {
			var cb = out.get();
			cb.handleSegment(ctx.user, header, packet);

			return 1;
		};
	}

	private final NativePacketProcessor outputOfArray(Supplier<OfArray<Object>> out) {
		return (header, packet, ctx) -> {
			var hdr = new PcapHeader(header);
			var buf = packet.toArray(ValueLayout.JAVA_BYTE);

			var cb = out.get();
			cb.handleArray(ctx.user, hdr, buf);

			return 1;
		};
	}

	private final NativePacketProcessor outputOfByteBuffer(Supplier<OfByteBuffer<Object>> out) {
		return (header, packet, ctx) -> {
			var hdr = new PcapHeader(header);
			var buf = packet.asByteBuffer();

			var cb = out.get();
			cb.handleByteBuffer(ctx.user, hdr, buf);

			return 1;
		};
	}

	private final NativePacketProcessor outputNativeCallback(Supplier<NativeCallback> out,
			OutputTransformer<?, ?> output) {
		return (header, packet, ctx) -> {
			var cb = out.get();
			cb.nativeCallback((MemorySegment) ctx.user, header, packet);

			return 1;
		};
	}

	private final NativeCallback inputNativeCallback(Supplier<NativePacketProcessor> out,
			InputTransformer<?, ?> input) {
		return (_, header, packet) -> {
			if (header.byteSize() == 0)
				header = header.reinterpret(24);

			if (packet.byteSize() == 0)
				packet = packet.reinterpret(PCAP_ABI.captureLength(header));

			ctx.reset();

			var np = out.get();
			int count = np.processNativePacket(header, packet, ctx);
			ctx.packetCount = count;

		};
	}

	private NativeCallback getNativeCallbackInput() {
		return this.inputNativeCallback;
	}

	private <U> void switchToByteBufferCallback(OfByteBuffer<U> cb, U user) {
		cbSwitch.select(BUFFER_CB);
		ctx.user = user;

		cbSwitchOfByteBuffer.accept(cb);
	}

	private <U> void switchToArrayCallback(OfArray<U> cb, U user) {
		cbSwitch.select(ARRAY_CB);
		ctx.user = user;

		cbSwitchOfArray.accept(cb);
	}

	private void switchToNativeCallback(NativeCallback cb, MemorySegment user) {
		cbSwitch.select(NATIVE_CB);
		ctx.user = user;

		cbSwitchNativeCallback.accept(cb);;
	}

	private <U> void switchToMemoryCallback(OfMemorySegment<U> cb, U user) {
		cbSwitch.select(MEMORY_SEGMENT_CB);
		ctx.user = user;

		cbSwitchOfMemorySegment.accept(cb);
	}

	private void resetSwitch() {
		cbSwitch.reset();
	}

	@Override
	public <U> int dispatchSegment(int count, OfMemorySegment<U> memorySegmentHandler, U user) {

		this.switchToMemoryCallback(memorySegmentHandler, user);

		pcap.dispatch(count, this.getNativeCallbackInput(), MemorySegment.NULL);

		this.resetSwitch();

		return ctx.packetCount;
	}

	@Override
	public int dispatchNative(int count, NativeCallback handler, MemorySegment user) {

		this.switchToNativeCallback(handler, user);

		pcap.dispatch(count, this.getNativeCallbackInput(), MemorySegment.NULL);

		this.resetSwitch();

		return ctx.packetCount;
	}

	@Override
	public <U> int dispatchArray(int count, OfArray<U> cb, U user) {
		this.switchToArrayCallback(cb, user);

		pcap.dispatch(count, this.getNativeCallbackInput(), MemorySegment.NULL);

		this.resetSwitch();

		return ctx.packetCount;
	}

	@Override
	public <U> int dispatchBuffer(int count, OfByteBuffer<U> cb, U user) {

		this.switchToByteBufferCallback(cb, user);

		pcap.dispatch(count, this.getNativeCallbackInput(), MemorySegment.NULL);

		this.resetSwitch();

		return ctx.packetCount;
	}

	@Override
	public boolean nextPacket(Packet packetReference) {
		assert packetReference.descriptor().type() == PacketDescriptorType.PCAP
				: "packet descriptor must be PcapDescriptor type";

		int count = dispatchNative(1, new NativeCallback() {

			@Override
			public void nativeCallback(MemorySegment user, MemorySegment header, MemorySegment packet) {
				PcapHeader pcapHeader = new PcapHeader(header);
				long timestamp = pcapHeader.timestamp();
				int caplen = pcapHeader.captureLength();
				int wirelen = pcapHeader.wireLength();

				pcapDescriptorReusable.initDescriptor(timestamp, caplen, wirelen);

				var newPacket = Arena.ofAuto().allocate(packet.byteSize()).copyFrom(packet);

				packetReference.bind(newPacket.asByteBuffer(), newPacket);
				packetReference.descriptor()
						.withBinding(pcapDescriptorReusable.buffer(), pcapDescriptorReusable.memorySegment());

			}

		}, MemorySegment.NULL);

		return ctx.packetCount > 0;
	}
}
