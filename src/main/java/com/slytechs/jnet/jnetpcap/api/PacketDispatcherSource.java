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
package com.slytechs.jnet.jnetpcap.api;

import java.util.function.LongUnaryOperator;

import com.slytechs.jnet.protocol.api.packet.Packet;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface PacketDispatcherSource extends LongUnaryOperator {

	Packet DEFAULT_PACKET = new Packet();

	static PacketDispatcherSource from(LongUnaryOperator src) {
		return cnt -> src.applyAsLong(cnt);
	}

	default Packet getDefaultPacket() {
		return DEFAULT_PACKET;
	}

	long captureFromSource(long packetCount);

	/**
	 * @see java.util.function.LongUnaryOperator#applyAsLong(long)
	 */
	@Override
	default long applyAsLong(long packetCount) {
		return captureFromSource(packetCount);
	}
}
