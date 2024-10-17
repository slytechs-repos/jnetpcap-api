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

import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapHandler.NativeCallback;

import com.slytechs.jnet.jnetpcap.NativePacketPipeline.StatefulNativePacket;
import com.slytechs.jnet.jnetruntime.pipeline.AbstractInput;
import com.slytechs.jnet.jnetruntime.pipeline.AbstractOutput;
import com.slytechs.jnet.jnetruntime.pipeline.AbstractPipeline;
import com.slytechs.jnet.jnetruntime.pipeline.DataTransformer.InputTransformer.EntryPoint;
import com.slytechs.jnet.jnetruntime.pipeline.DataTransformer.OutputTransformer.EndPoint;
import com.slytechs.jnet.jnetruntime.pipeline.HeadNode;
import com.slytechs.jnet.jnetruntime.pipeline.MultiEndPoint;
import com.slytechs.jnet.jnetruntime.pipeline.TailNode;
import com.slytechs.jnet.jnetruntime.util.Registration;

/**
 * @author Mark Bednarczyk
 */
public class NativePacketPipeline
		extends AbstractPipeline<StatefulNativePacket, NativePacketPipeline> {

	public static class NativeProcessorContext {

		MemorySegment userData;

	}

	public interface StatefulNativePacket {
		void processNativePacket(MemorySegment header, MemorySegment packet, NativeProcessorContext context);
	}

	public static class PcapCallback
			extends AbstractInput<NativeCallback, StatefulNativePacket, PcapCallback>
			implements NativeCallback {

		private NativeProcessorContext context;

		/**
		 * @param headNode
		 * @param name
		 * @param inputType
		 * @param outputType
		 */
		public PcapCallback(
				HeadNode<StatefulNativePacket> headNode) {
			super(headNode, "input", PcapDataType.PCAP_NATIVE_PACKET, NetDataTypes.STATEFUL_NATIVE_PACKET);

			this.context = new NativeProcessorContext();
		}

		/**
		 * @see org.jnetpcap.PcapHandler.NativeCallback#nativeCallback(java.lang.foreign.MemorySegment,
		 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
		 */
		@Override
		public void nativeCallback(MemorySegment user, MemorySegment header, MemorySegment packet) {
			context.userData = user;

			try {
				readLock.lock();
				outputData().processNativePacket(header, packet, context);

			} finally {
				readLock.unlock();
			}
		}
	}

	public static class OfNativeOutput
			extends AbstractOutput<StatefulNativePacket, NativeCallback, OfNativeOutput>
			implements StatefulNativePacket {

		/**
		 * @param tailNode
		 * @param name
		 * @param inputType
		 * @param outputType
		 */
		public OfNativeOutput(TailNode<StatefulNativePacket> tailNode) {
			super(tailNode, "OfNativeOutput", NetDataTypes.STATEFUL_NATIVE_PACKET, PcapDataType.PCAP_NATIVE_PACKET);
		}

		/**
		 * @see com.slytechs.jnet.jnetpcap.NativePacketPipeline.StatefulNativePacket#processNativePacket(java.lang.foreign.MemorySegment,
		 *      java.lang.foreign.MemorySegment,
		 *      com.slytechs.jnet.jnetpcap.NativePacketPipeline.NativeProcessorContext)
		 */
		@Override
		public void processNativePacket(MemorySegment header, MemorySegment packet, NativeProcessorContext context) {
			outputData().nativeCallback(context.userData, header, packet);
		}

	}

	public static class OfSegmentOutput
			extends AbstractOutput<StatefulNativePacket, PcapHandler.OfMemorySegment<?>, OfSegmentOutput>
			implements StatefulNativePacket {

		/**
		 * @param tailNode
		 * @param name
		 * @param inputType
		 * @param outputType
		 */
		public OfSegmentOutput(TailNode<StatefulNativePacket> tailNode) {
			super(tailNode, "OfSegmentOutput",
					NetDataTypes.STATEFUL_NATIVE_PACKET,
					NetDataTypes.PCAP_PACKET_OF_SEGMENT);
		}

		/**
		 * @see com.slytechs.jnet.jnetpcap.NativePacketPipeline.StatefulNativePacket#processNativePacket(java.lang.foreign.MemorySegment,
		 *      java.lang.foreign.MemorySegment,
		 *      com.slytechs.jnet.jnetpcap.NativePacketPipeline.NativeProcessorContext)
		 */
		@Override
		public void processNativePacket(MemorySegment header, MemorySegment packet, NativeProcessorContext context) {
			outputData().handleSegment(null, header, packet);
		}

	}

	private final EntryPoint<NativeCallback> entryPoint;
	private final EndPoint<NativeCallback> endPointOfNativeMulti;
	private EndPoint<NativeCallback> endPointOfNativeSingle;
	private EndPoint<PcapHandler.OfMemorySegment<?>> endPointOfSegment;
	private OfNativeOutput nativeOutput;

	public NativePacketPipeline(String name) {
		super(name, NetDataTypes.STATEFUL_NATIVE_PACKET);

		var pcapInput = this.addInput(NativePacketPipeline.PcapCallback::new);
		this.entryPoint = pcapInput.createEntryPoint(name());

		this.nativeOutput = this.addOutput(NativePacketPipeline.OfNativeOutput::new);
		this.endPointOfNativeMulti = nativeOutput
				.createEndPoint(name(), MultiEndPoint::new);

	}

	public EntryPoint<NativeCallback> entryPoint() {
		return entryPoint;
	}

	public EndPoint<NativeCallback> endPointOfNative() {
		if (endPointOfNativeSingle == null)
			this.endPointOfNativeSingle = nativeOutput
					.createMutableEndPoint(name())
					.resetAsEmpty();

		return endPointOfNativeSingle;
	}

	public EndPoint<PcapHandler.OfMemorySegment<?>> endPointOfSegment() {
		if (endPointOfSegment == null)
			this.endPointOfSegment = this.addOutput(NativePacketPipeline.OfSegmentOutput::new)
					.createMutableEndPoint(name())
					.resetAsEmpty();

		return endPointOfSegment;
	}

	public Registration link(EntryPoint<NativeCallback> entryPoint) {
		assert entryPoint.dataType() == endPointOfNative().dataType();

		final NativeCallback data = entryPoint.data();
		endPointOfNativeMulti.data(data);

		return endPointOfNativeSingle::clear;
	}
}
