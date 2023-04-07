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

import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;
import com.slytechs.jnet.runtime.util.MemoryUnit;
import com.slytechs.jnetpcap.pro.internal.JavaPacketDispatcher;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class JavaIpfDispatcher extends JavaPacketDispatcher implements IpfDispatcher {

	/**
	 * @param pcapHandle
	 * @param breakDispatch
	 * @param descriptorType
	 */
	public JavaIpfDispatcher(MemoryAddress pcapHandle, Runnable breakDispatch, PacketDescriptorType descriptorType) {
		super(pcapHandle, breakDispatch, descriptorType);
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.ipf.IpfDispatcher#setIpfTableSize(int,
	 *      long, com.slytechs.jnet.runtime.util.MemoryUnit)
	 */
	@Override
	public void setIpfTableSize(int entryCount, long bufferSize, MemoryUnit unit) {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
