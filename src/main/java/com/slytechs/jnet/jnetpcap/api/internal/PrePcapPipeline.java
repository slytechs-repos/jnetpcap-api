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
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.util.function.Supplier;

import org.jnetpcap.PcapHeader;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.jnet.jnetpcap.api.PacketHandler;
import com.slytechs.jnet.jnetpcap.api.PacketHandler.OfArray;
import com.slytechs.jnet.jnetpcap.api.PacketHandler.OfBuffer;
import com.slytechs.jnet.jnetpcap.api.PacketHandler.OfForeign;
import com.slytechs.jnet.jnetpcap.api.PacketHandler.OfNative;
import com.slytechs.jnet.jnetpcap.api.processors.PreProcessors;
import com.slytechs.jnet.jnetpcap.api.processors.PreProcessors.PreProcessor;
import com.slytechs.jnet.platform.api.frame.FrameABI;
import com.slytechs.jnet.platform.api.frame.PcapFrameHeader;
import com.slytechs.jnet.platform.api.pipeline.DataLiteral;
import com.slytechs.jnet.platform.api.pipeline.InputTransformer;
import com.slytechs.jnet.platform.api.pipeline.OutputStack;
import com.slytechs.jnet.platform.api.pipeline.OutputTransformer;
import com.slytechs.jnet.platform.api.pipeline.OutputTransformer.OutputMapper;
import com.slytechs.jnet.platform.api.pipeline.Pipeline;
import com.slytechs.jnet.platform.api.time.FrameStopwatch;
import com.slytechs.jnet.platform.api.time.TimestampUnit;
import com.slytechs.jnet.platform.api.util.Registration;
import com.slytechs.jnet.protocol.api.descriptor.PcapDescriptor;
import com.slytechs.jnet.protocol.api.packet.Packet;
import com.slytechs.jnet.protocol.tcpip.constants.PacketDescriptorType;

/**
 * @author Mark Bednarczyk
 */
public final class PrePcapPipeline
		extends Pipeline<PreProcessor>
		implements PreProcessors {

	/**
	 * @author Mark Bednarczyk [mark@slytechs.com]
	 * @author Sly Technologies Inc.
	 */
	public static class PreContext {
		public final PcapFrameHeader pcapHeader;
		public MemorySegment pcapSegment;
		public ByteBuffer pcapBuffer;
		public final TimestampUnit pcapTsUnit;

		public Object user;
		public long packetCount;
		public long lastPacketTs;
		public final FrameABI abi;

		public final FrameStopwatch frameStopwatch = new FrameStopwatch();

		public PreContext(FrameABI frameABI, TimestampUnit pcapTsUnit) {
			this.pcapTsUnit = pcapTsUnit;
			this.abi = frameABI;

			this.pcapHeader = new PcapFrameHeader(frameABI, pcapTsUnit);
		}

		public void reset() {
//			this.packetCount = 0;
			this.user = null;
		}
	}

	private final OfNative mainInput;
	private final PreContext ctx;

	private final PcapDescriptor pcapDescriptorReusable = new PcapDescriptor();
	private final OutputStack<PreProcessor> cbStack;
	private final OutputTransformer<PreProcessor, OfNative> nativeOutput;
	private final OutputTransformer<PreProcessor, OfArray<Object>> arrayOutput;
	private final OutputTransformer<PreProcessor, OfBuffer<Object>> bufferOutput;
	private final OutputTransformer<PreProcessor, OfForeign<Object>> foreignOutput;
	private final PcapSource pcapSource;

	/**
	 * @param name
	 * @param reducer
	 */
	public PrePcapPipeline(String deviceName, NetPcap pcap, FrameABI frameABI, PcapSource source) {
		super(deviceName, new DataLiteral<>(PreProcessor.class));
		this.pcapSource = source;

		this.ctx = new PreContext(frameABI, TimestampUnit.PCAP_MICRO);

		var mseg = Arena.ofAuto().allocate(PcapDescriptor.PCAP_DESCRIPTOR_LENGTH);
		this.pcapDescriptorReusable.bind(mseg.asByteBuffer(), mseg);

		this.mainInput = head()
				.addInput("OfNative", this::inputOfNative, new DataLiteral<>(OfNative.class))
				.getInputPerma(); // Guaranteed it will never change

		this.cbStack = tail().getOutputStack();
		this.nativeOutput = cbStack.createTransformer(
				"OfNative", this::outputOfNative, new DataLiteral<>(OfNative.class));
		this.arrayOutput = cbStack.createTransformer(
				"OfArray", this::outputOfArray, new DataLiteral<OfArray<Object>>() {});
		this.bufferOutput = cbStack.createTransformer(
				"OfBuffer", this::outputOfBuffer, new DataLiteral<OfBuffer<Object>>() {});
		this.foreignOutput = cbStack.createTransformer(
				"OfForeign", this::outputOfForeign, new DataLiteral<OfForeign<Object>>() {});

	}

	public Registration addOutput(Object id, OfNative handler) {
		var output = cbStack.createTransformer(id, new OutputMapper<PreProcessor, OfNative>() {

			@Override
			public PreProcessor createMappedOutput(Supplier<OfNative> sink,
					OutputTransformer<PreProcessor, OfNative> output) {
				return (header, packet, context) -> {
					sink.get().handleNative(MemorySegment.NULL, header, packet);

					return 1;
				};
			}
		}, new DataLiteral<OfNative>(OfNative.class));

		output.connect(handler);

		cbStack.push(output);

		return () -> {
			output.disconnect();
			cbStack.remove(output);
		};
	}

	public long capturePackets(long count) {
		/*
		 * The value 0 has a different meaning - it indicates to process all packets
		 * currently in the buffer (for offline captures) or to wait for and process
		 * packets until a read timeout occurs (for live captures).
		 */
		if (count == -1 || count == 0)
			pcapSource.dispatchNative((int) count, getOfNativeInput(), MemorySegment.NULL);

		else {
			while (count > 0) {
				int count32 = (count > Integer.MAX_VALUE)
						? Integer.MAX_VALUE
						: (int) count;

				int r = pcapSource.dispatchNative(count32, getOfNativeInput(), MemorySegment.NULL);
				if (r < 0)
					break;

				count -= count32;
			}
		}

		return ctx.packetCount;
	}

	@SuppressWarnings("unchecked")
	public <U> long dispatchArray(long count, PacketHandler.OfArray<U> handler, U user) {

		ctx.user = user;

		try (var _ = arrayOutput.connect((OfArray<Object>) handler);
				var _ = cbStack.push(arrayOutput)) {

			capturePackets(count);
		}

		return ctx.packetCount;
	}

	@SuppressWarnings("unchecked")
	public <U> long dispatchBuffer(long count, OfBuffer<U> handler, U user) {

		ctx.user = user;

		try (var _ = bufferOutput.connect((OfBuffer<Object>) handler);
				var _ = cbStack.push(bufferOutput)) {

			capturePackets(count);
		}
		return ctx.packetCount;
	}

	@SuppressWarnings("unchecked")
	public <U> long dispatchForeign(long count, OfForeign<U> handler, U user) {

		ctx.user = user;

		try (var _ = foreignOutput.connect((OfForeign<Object>) handler);
				var _ = cbStack.push(foreignOutput)) {

			capturePackets(count);
		}

		return ctx.packetCount;
	}

	public long dispatchNative(long count, OfNative handler, MemorySegment user) {

		ctx.user = user;

		try (var _ = nativeOutput.connect(handler);
				var _ = cbStack.push(nativeOutput)) {

			capturePackets(count);
		}

		return ctx.packetCount;
	}

	private OfNative getOfNativeInput() {
		return this.mainInput;
	}

	private final OfNative inputOfNative(Supplier<PreProcessor> out,
			InputTransformer<?, ?> input) {
		return (_, header, packet) -> {
			ctx.reset();

			// Setup the PcapHeader so we can read the fields
			ctx.pcapSegment = header;
			ctx.pcapBuffer = header.asByteBuffer();
			ctx.pcapHeader.withBinding(ctx.pcapBuffer, ctx.pcapSegment);

			// Setup IFG frame tracking, auto-closeable but reusing the same stopwatch
			try (var _ = ctx.frameStopwatch.start(ctx.pcapHeader)) {

				var nextProcessor = out.get();
				long pktsProcessedInPipe = nextProcessor.preProcessPacket(header, packet, ctx);

				ctx.packetCount += pktsProcessedInPipe;
			}

		};
	}

	public boolean nextPacket(Packet packetReference) {
		assert packetReference.descriptor().type() == PacketDescriptorType.PCAP
				: "packet descriptor must be PcapDescriptor type";

		dispatchNative(1, new OfNative() {

			@Override
			public void handleNative(MemorySegment user, MemorySegment header, MemorySegment packet) {
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

	private final PreProcessor outputOfArray(Supplier<PacketHandler.OfArray<Object>> out) {
		return (header, packet, ctx) -> {
			var array = packet.toArray(ValueLayout.JAVA_BYTE);

			var cb = out.get();
			cb.handleArray(ctx.user, ctx.pcapHeader, array);

			return 1;
		};
	}

	private final PreProcessor outputOfBuffer(Supplier<OfBuffer<Object>> out) {
		return (header, packet, ctx) -> {
			var buf = packet.asByteBuffer();

			var cb = out.get();
			cb.handleBuffer(ctx.user, ctx.pcapHeader, buf);

			return 1;
		};
	}

	private final PreProcessor outputOfForeign(Supplier<OfForeign<Object>> out) {
		return (header, packet, ctx) -> {
			var cb = out.get();
			cb.handleForeign(ctx.user, ctx.pcapHeader, packet);

			return 1;
		};
	}

	private final PreProcessor outputOfNative(Supplier<OfNative> out,
			OutputTransformer<?, ?> output) {
		return (header, packet, ctx) -> {
			var cb = out.get();
			cb.handleNative((MemorySegment) ctx.user, header, packet);

			return 1;
		};
	}
}
