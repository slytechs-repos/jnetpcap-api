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
package com.slytechs.jnetpcap.pro.internal.ipf;

import java.lang.foreign.MemoryAddress;

import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.internal.PcapForeignDowncall;
import org.jnetpcap.internal.PcapForeignInitializer;

import com.slytechs.jnetpcap.pro.IpfReassembler;
import com.slytechs.jnetpcap.pro.internal.AbstractPacketDispatcher;
import com.slytechs.jnetpcap.pro.internal.PacketDispatcher;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class IpfDispatcherNative
		extends AbstractPacketDispatcher
		implements IpfDispatcher {

	private MemoryAddress ipfTable;

	/**
	 * @param pcapHandle
	 * @param breakDispatch
	 * @param descriptorType
	 */
	public IpfDispatcherNative(
			PcapDispatcher pcap,
			PacketDispatcher packet,
			IpfReassembler config) {

		super(packet, pcap);
	}

	private static final PcapForeignDowncall ipf_allocate_table;

	static {
		try (var foreign = new PcapForeignInitializer(IpfDispatcherNative.class)) {
			ipf_allocate_table = foreign.downcall("ipf_allocate_table(IJ)A");
		}
	}

	static boolean isNativeSupported() {
		return ipf_allocate_table.isNativeSymbolResolved();
	}

}
