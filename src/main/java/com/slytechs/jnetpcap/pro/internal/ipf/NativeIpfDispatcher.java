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

import org.jnetpcap.internal.PcapForeignDowncall;
import org.jnetpcap.internal.PcapForeignInitializer;

import com.slytechs.jnetpcap.pro.internal.JavaPacketDispatcher;
import com.slytechs.protocol.pack.core.constants.PacketDescriptorType;
import com.slytechs.protocol.runtime.util.MemoryUnit;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class NativeIpfDispatcher
		extends JavaPacketDispatcher
		implements IpfDispatcher {

	private MemoryAddress ipfTable;

	/**
	 * @param pcapHandle
	 * @param breakDispatch
	 * @param descriptorType
	 */
	public NativeIpfDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			PacketDescriptorType descriptorType) {

		super(pcapHandle, breakDispatch, descriptorType);
	}

	private static final PcapForeignDowncall ipf_allocate_table;

	static {
		try (var foreign = new PcapForeignInitializer(NativeIpfDispatcher.class)) {
			ipf_allocate_table = foreign.downcall("ipf_allocate_table(IJ)A");
		}
	}

	static boolean isNativeSupported() {
		return ipf_allocate_table.isNativeSymbolResolved();
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfDispatcher#setIpfTableSize(int,
	 *      long, com.slytechs.protocol.runtime.util.MemoryUnit)
	 */
	@Override
	public void setIpfTableSize(int entryCount, long bufferSize, MemoryUnit unit) {
		this.ipfTable = (MemoryAddress) ipf_allocate_table
				.invokeObj(entryCount, unit.toBytes(bufferSize));
	}

}
