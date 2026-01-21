/*
 * Copyright 2005-2025 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.jnetpcap.api;

import java.lang.foreign.MemorySegment;

import com.slytechs.sdk.common.memory.Memory;
import com.slytechs.sdk.common.time.TimestampUnit;
import com.slytechs.sdk.jnetpcap.Pcap;
import com.slytechs.sdk.jnetpcap.internal.PcapHeaderABI;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.PacketSettings;
import com.slytechs.sdk.protocol.core.descriptor.AbstractPacketDescriptor;
import com.slytechs.sdk.protocol.core.descriptor.DescriptorInfo;
import com.slytechs.sdk.protocol.core.dissector.Type2PacketDissector;
import com.slytechs.sdk.protocol.core.dissector.OnDemandPacketDissector;
import com.slytechs.sdk.protocol.core.dissector.PacketDissector;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
class PacketPipeline {

	private final Pcap pcap;
	private final PacketSettings settings;
	private final Packet packet;
	private final PcapHeaderABI abi;
	private final PacketDissector dissector;
	private TimestampUnit timestampUnit = TimestampUnit.EPOCH_MICRO;

	public PacketPipeline(Pcap pcap, PcapHeaderABI abi, PacketSettings settings) {
		this.pcap = pcap;
		this.abi = abi;
		this.settings = settings;
		this.packet = createPacket(settings);
		this.dissector = createDissector(settings);
	}

	private PacketDissector createDissector(PacketSettings settings) {
		if (settings.isDissectionEnabled() && settings.isEagerDissection()) {
			return new Type2PacketDissector();
		}

		return null;
	}

	private Packet createPacket(PacketSettings settings) {
		if (settings.isDissectionEnabled() && settings.isEagerDissection()) {
			return Packet.ofHybridType(DescriptorInfo.TYPE2);

		} else {
			var pkt = Packet.ofScopedType(DescriptorInfo.PCAP_PADDED);
			var desc = ((AbstractPacketDescriptor) pkt.descriptor());

			if (settings.isOnDemandDissection())
				desc.setOnDemandDissector(OnDemandPacketDissector::bindHeader);

			return pkt;
		}
	}

	private void dissectPacket(MemorySegment pcapHdr, Packet packet) {
		assert dissector != null
				: "Missing dissector";

		assert packet.descriptor()
				.boundMemory()
				.isFixed()
				: "Invalid packet structure, expecting a FixedMemory pre-bound to descriptor";

		int caplen = abi.captureLength(pcapHdr);
		int wirelen = abi.wireLength(pcapHdr);
		long tvSec = abi.tvSec(pcapHdr);
		long tvUsec = abi.tvUsec(pcapHdr);
		long timestamp = timestampUnit.ofSecond(tvSec, tvUsec);

		// Raw native packet memory we need to dissect
		Memory pktMemory = packet.boundMemory();

		dissector.dissectPacket(pktMemory, timestamp, caplen, wirelen);
		dissector.writeDescriptor(packet.descriptor());
	}

	private Packet rebindPacket(MemorySegment pcapHdr, MemorySegment data) {
		// Binding to pre-allocated/bound ScopedMemory to data offset + length
		packet.boundMemory()
				.asScopedMemory()
				.bind(data, 0, data.byteSize());

		return packet;
	}

	private void rebindPcapHeader(MemorySegment pcapHdr, Packet packet) {
		packet.descriptor()
				.boundMemory()
				.asScopedMemory()
				.bind(pcapHdr, 0, abi.headerLength());
	}

	public Packet processPacket(MemorySegment pcapHdr, MemorySegment data) {
		Packet packet = rebindPacket(pcapHdr, data);

		if (dissector == null)
			rebindPcapHeader(pcapHdr, packet);
		else
			dissectPacket(pcapHdr, packet);

		return packet;
	}

}
