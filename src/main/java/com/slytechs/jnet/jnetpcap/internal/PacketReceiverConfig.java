/*
 * Copyright 2024 Sly Technologies Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.jnet.jnetpcap.internal;

import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnet.jnetruntime.time.TimestampUnit;
import com.slytechs.jnet.protocol.Frame.FrameNumber;
import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.descriptor.PacketDissector;
import com.slytechs.jnet.protocol.meta.PacketFormat;

/**
 * The Class PacketReceiverConfig.
 */
public class PacketReceiverConfig {

	/**
	 * Instantiates a new packet receiver config.
	 */
	public PacketReceiverConfig() {

	}

	/** The port no. */
	public int portNo;

	/** The port name. */
	public String portName = "";

	/** The frame no. */
	public FrameNumber frameNo = FrameNumber.of();

	/** The timestamp unit. */
	public TimestampUnit timestampUnit = TimestampUnit.PCAP_MICRO;

	/** The formatter. */
	public PacketFormat formatter;

	/** The dissector. */
	public PacketDissector dissector;

	/** The descriptor type. */
	public PacketDescriptorType descriptorType = PacketDescriptorType.TYPE2;

	/** The abi. */
	public PcapHeaderABI abi;

}