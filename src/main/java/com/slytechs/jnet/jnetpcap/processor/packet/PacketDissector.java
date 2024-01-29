/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
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
package com.slytechs.jnet.jnetpcap.processor.packet;

import java.util.function.Supplier;

import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacket;
import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacketConsumer;
import com.slytechs.jnet.jnetpcap.processor.AbstractProcessor;
import com.slytechs.jnet.jnetpcap.processor.ProcessorType;
import com.slytechs.jnet.jnetpcap.processor.protocol.ProtocolProcessor;
import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class PacketDissector extends AbstractProcessor<PacketDissector> implements ProtocolProcessor {

	public PacketDissector(int priority) {
		super(ProcessorType.PACKET, priority);
	}

	public PacketDissector descriptor(PacketDescriptorType type) {
		throw new UnsupportedOperationException();
	}

	public PacketDissector packetFactory(Supplier<Packet> newPacketFactory) {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.processor.protocol.ProtocolProcessor#forEach(com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacket,
	 *      java.lang.Object)
	 */
	@Override
	public <U> ProtocolProcessor forEach(OfPacket<U> packet, U userData) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.processor.protocol.ProtocolProcessor#forEach(com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacketConsumer)
	 */
	@Override
	public <U> ProtocolProcessor forEach(OfPacketConsumer packet) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.processor.protocol.ProtocolProcessor#peek(com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacket,
	 *      java.lang.Object)
	 */
	@Override
	public <U> ProtocolProcessor peek(OfPacket<U> packet, U userData) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.processor.protocol.ProtocolProcessor#peek(com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacketConsumer)
	 */
	@Override
	public <U> ProtocolProcessor peek(OfPacketConsumer packet) {
		throw new UnsupportedOperationException("not implemented yet");
	}

}