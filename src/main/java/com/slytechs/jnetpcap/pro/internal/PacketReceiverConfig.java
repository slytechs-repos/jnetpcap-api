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
package com.slytechs.jnetpcap.pro.internal;

import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.protocol.Frame.FrameNumber;
import com.slytechs.protocol.descriptor.PacketDissector;
import com.slytechs.protocol.meta.PacketFormat;
import com.slytechs.protocol.pack.core.constants.PacketDescriptorType;
import com.slytechs.protocol.runtime.time.TimestampUnit;

/**
 * The Class PacketReceiverConfig.
 */
public class PacketReceiverConfig {

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