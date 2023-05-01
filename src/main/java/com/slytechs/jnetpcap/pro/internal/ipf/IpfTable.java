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

import com.slytechs.jnetpcap.pro.IpfConfiguration;
import com.slytechs.jnetpcap.pro.internal.ipf.JavaIpfDispatcher.PacketInserter;
import com.slytechs.protocol.descriptor.IpfFragment;
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

	/**
	 * Allocate ipf buffer slice.
	 *
	 * @param index the index
	 * @return the ipf reassembler
	 */
	private IpfReassembler allocateIpfBufferSlice(int index) {
		int sliceSize = this.bufferSize / tableSize;
		int off = sliceSize * index;

		ByteBuffer slice = buffer.slice(off, sliceSize);
		HashEntry<IpfReassembler> entry = table.get(index);

		return new IpfReassembler(slice, entry, config);
	}

	/** The buffer. */
	private final ByteBuffer buffer;

	/** The table. */
	private final HashTable<IpfReassembler> table;

	/** The buffer size. */
	private final int bufferSize;

	/** The config. */
	private final IpfConfiguration config;

	/** The table size. */
	private final int tableSize;

	private final TimeoutQueue<IpfReassembler> timeoutQueue;
	private final PacketInserter packetInserter;

	/**
	 * Instantiates a new ipf table.
	 *
	 * @param config the config
	 */
	public IpfTable(IpfConfiguration config, PacketInserter packetInserter) {
		this(config, ByteBuffer.allocateDirect(config.getIpfBufferSize()), packetInserter);
	}

	/**
	 * Instantiates a new ipf table.
	 *
	 * @param config the config
	 * @param buffer the buffer
	 */
	public IpfTable(IpfConfiguration config, ByteBuffer buffer, PacketInserter packetInserter) {
		this.config = config;
		this.packetInserter = packetInserter;
		this.bufferSize = config.getIpfBufferSize();
		this.buffer = buffer;
		this.tableSize = config.getIpfTableSize();

		this.table = new CuckooHashTable<IpfReassembler>(config.getIpfTableSize())
				.enableStickyData(true);

		this.table.fill(this::allocateIpfBufferSlice);
		this.timeoutQueue = new TimeoutQueue<>(config.getTimeoutQueueSize(), config.getTimeSource());
	}

	/**
	 * Lookup.
	 *
	 * @param desc     the desc
	 * @param hashcode the hashcode
	 * @return the ipf reassembler
	 */
	public IpfReassembler lookup(IpfFragment desc, long hashcode) {
		var key = desc.keyBuffer();
		assert key.remaining() > 0 : "key has no data";

		int index = table.add(key, null, hashcode);
		if (index == -1)
			return null; // Out of table space

		var entry = table.get(index);
		var ipf = entry.data();
		if (ipf.isExpired()) {
			ipf.reset(key);

			final var registration = timeoutQueue.add(ipf, this::onIpfTimeout);
			ipf.setCancelTimeoutRegistration(registration);
		}

		return ipf;
	}

	private void onIpfTimeout(IpfReassembler timedoutReassembler) {
		timedoutReassembler.timeoutOnDurationExpired(packetInserter);
	}
}
