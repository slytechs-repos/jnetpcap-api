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

import java.util.function.Function;

import org.jnetpcap.PcapHandler;

import com.slytechs.jnet.jnetpcap.NativePacketPipeline.StatefulNativePacket;
import com.slytechs.jnet.jnetpcap.PacketPipeline.StatefulPacket;
import com.slytechs.jnet.jnetpcap.RawPacketPipeline.StatefulRawPacket;
import com.slytechs.jnet.jnetruntime.pipeline.DataType;
import com.slytechs.jnet.protocol.core.network.IpPipeline.StatefulIpf;

public enum NetDataTypes implements DataType {
	STATEFUL_NATIVE_PACKET(StatefulNativePacket.class, NetDataTypes::arrayWrapper),
	STATEFUL_RAW_PACKET(StatefulRawPacket.class, NetDataTypes::arrayWrapper),
	STATEFUL_PACKET(StatefulPacket.class, NetDataTypes::arrayWrapper),
	STATEFUL_IPF(StatefulIpf.class, NetDataTypes::arrayWrapper),
	PCAP_PACKET_OF_ARRAY(PcapHandler.OfArray.class, NetDataTypes::arrayWrapper),
	PCAP_PACKET_OF_BUFFER(PcapHandler.OfByteBuffer.class, NetDataTypes::arrayWrapper),
	PCAP_PACKET_OF_SEGMENT(PcapHandler.OfMemorySegment.class, NetDataTypes::arrayWrapper),
	OF_PACKET(NetPcapHandler.OfPacket.class, NetDataTypes::arrayWrapper),

	;

	private static StatefulNativePacket arrayWrapper(StatefulNativePacket[] array) {
		return (u, h, p) -> {
			for (var a : array) {
				a.processNativePacket(u, h, p);
			}
		};
	}

	private static StatefulRawPacket arrayWrapper(StatefulRawPacket[] array) {
		return (u, h, p) -> {
			for (var a : array) {
				a.processRawPacket(u, h, p);
			}
		};
	}

	private static <U> PcapHandler.OfArray<U> arrayWrapper(PcapHandler.OfArray<U>[] array) {
		return (u, h, p) -> {
			for (var a : array) {
				a.handleArray(u, h, p);
			}
		};
	}

	private static <U> PcapHandler.OfByteBuffer<U> arrayWrapper(PcapHandler.OfByteBuffer<U>[] array) {
		return (u, h, p) -> {
			for (var a : array) {
				a.handleByteBuffer(u, h, p);
			}
		};
	}

	private static <U> PcapHandler.OfMemorySegment<U> arrayWrapper(PcapHandler.OfMemorySegment<U>[] array) {
		return (u, h, p) -> {
			for (var a : array) {
				a.handleSegment(u, h, p);
			}
		};
	}

	private static StatefulPacket arrayWrapper(StatefulPacket[] array) {
		return (pkt, ctx) -> {
			for (var a : array) {
				a.handlePacket(pkt, ctx);
			}
		};
	}

	private static StatefulIpf arrayWrapper(StatefulIpf[] array) {
		return (mseg, buf, ts, caplen, wirelen, ipf) -> {
			for (var a : array) {
				a.handleIpf(mseg, buf, ts, caplen, wirelen, ipf);
			}
		};
	}

	private static <U> NetPcapHandler.OfPacket<U> arrayWrapper(NetPcapHandler.OfPacket<U>[] array) {
		return (user, packet) -> {
			for (var a : array) {
				a.handlePacket(user, packet);
			}
		};
	}

	/** The data settingsSupport. */
	private final DataSupport<?> dataSupport;

	<T> NetDataTypes(Class<T> dataClass, Function<T[], T> arrayHandler) {
		this.dataSupport = new DataSupport<T>(this, dataClass, arrayHandler);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <T> DataSupport<T> dataSupport() {
		return (DataSupport<T>) dataSupport;
	}

}