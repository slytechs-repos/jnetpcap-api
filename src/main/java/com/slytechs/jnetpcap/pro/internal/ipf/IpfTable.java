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

import java.nio.ByteBuffer;

import com.slytechs.protocol.descriptor.IpfFragDescriptor;
import com.slytechs.protocol.runtime.hash.CuckooHashTable;
import com.slytechs.protocol.runtime.hash.HashTable;
import com.slytechs.protocol.runtime.hash.HashTable.HashEntry;

/**
 * IP Fragment tracking table.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class IpfTable {

	private IpfReassembler allocateIpfBufferSlice(int index) {
		int sliceSize = this.bufferSize / tableSize;
		int off = sliceSize * index;

		ByteBuffer slice = buffer.slice(off, sliceSize);
		HashEntry<IpfReassembler> entry = table.get(index);

		return new IpfReassembler(slice, entry, config);
	}

	private final ByteBuffer buffer;
	private final HashTable<IpfReassembler> table;
	private final int bufferSize;
	private final ByteBuffer key;
	private final IpfConfig config;
	private final int tableSize;

	public IpfTable(IpfConfig config) {
		this(config, ByteBuffer.allocateDirect(config.bufferSize));
	}

	public IpfTable(IpfConfig config, ByteBuffer buffer) {
		this.config = config;
		this.bufferSize = config.bufferSize;
		this.buffer = buffer;
		this.key = ByteBuffer.allocateDirect(HashTable.MAX_KEY_SIZE_BYTES);
		this.tableSize = config.tableSize;

		this.table = new CuckooHashTable<IpfReassembler>(config.tableSize)
				.enableStickyData(true);

		this.table.fill(this::allocateIpfBufferSlice);
	}

	public IpfReassembler lookup(IpfFragDescriptor desc, long hashcode) {
		var key = desc.keyBuffer();
		assert key.remaining() > 0;
		
		int index = table.add(key, null, hashcode);
		if (index == -1)
			return null; // Out of table space

		var entry = table.get(index);
		var ipf = entry.data();
		if (ipf.isExpired())
			ipf.reset(key);

		return ipf;
	}
}
