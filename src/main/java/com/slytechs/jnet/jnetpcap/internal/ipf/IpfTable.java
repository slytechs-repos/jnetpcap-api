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
package com.slytechs.jnet.jnetpcap.internal.ipf;

import java.nio.ByteBuffer;

import com.slytechs.jnet.jnetpcap.IpfReassembler;
import com.slytechs.jnet.jnetpcap.internal.ipf.JavaIpfDispatcher.DatagramQueue;
import com.slytechs.jnet.jnetruntime.hash.CuckooHashTable;
import com.slytechs.jnet.jnetruntime.hash.HashTable;
import com.slytechs.jnet.jnetruntime.hash.HashTable.HashEntry;
import com.slytechs.jnet.protocol.descriptor.IpfFragment;

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
	private IpfDgramReassembler allocateIpfBufferSlice(int index) {
		int sliceSize = this.bufferSize / tableSize;
		int off = sliceSize * index;

		ByteBuffer slice = buffer.slice(off, sliceSize);
		HashEntry<IpfDgramReassembler> entry = table.get(index);

		return new IpfDgramReassembler(slice, entry, config);
	}

	/** The buffer. */
	private final ByteBuffer buffer;

	/** The table. */
	private final HashTable<IpfDgramReassembler> table;

	/** The buffer size. */
	private final int bufferSize;

	/** The config. */
	private final IpfReassembler config;

	/** The table size. */
	private final int tableSize;

	/** The timeout queue. */
	private final TimeoutQueue<IpfDgramReassembler> timeoutQueue;
	
	/** The datagram queue. */
	private final DatagramQueue datagramQueue;

	/**
	 * Instantiates a new ipf table.
	 *
	 * @param config        the config
	 * @param datagramQueue the datagram queue
	 */
	public IpfTable(IpfReassembler config, DatagramQueue datagramQueue) {
		this(config, ByteBuffer.allocateDirect(config.getBufferSize()), datagramQueue);
	}

	/**
	 * Instantiates a new ipf table.
	 *
	 * @param config        the config
	 * @param buffer        the buffer
	 * @param datagramQueue the datagram queue
	 */
	public IpfTable(IpfReassembler config, ByteBuffer buffer, DatagramQueue datagramQueue) {
		this.config = config;
		this.datagramQueue = datagramQueue;
		this.bufferSize = config.getBufferSize();
		this.buffer = buffer;
		this.tableSize = config.getTableSize();

		this.table = new CuckooHashTable<IpfDgramReassembler>(config.getTableSize())
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
	public IpfDgramReassembler lookup(IpfFragment desc, long hashcode) {
		var key = desc.keyBuffer();
		assert key.remaining() > 0 : "key has no data";

		int index = table.add(key, null, hashcode);
		if (index == -1)
			return null; // Out of table space

		var entry = table.get(index);
		var reassembler = entry.data();
		if (reassembler.isExpired()) {
			reassembler.open(key);

			final var registration = timeoutQueue.add(reassembler, this::onIpfTimeout);
			reassembler.setTimeoutRegistration(registration);
		}

		return reassembler;
	}

	/**
	 * On ipf timeout.
	 *
	 * @param timedoutReassembler the timedout reassembler
	 */
	private void onIpfTimeout(IpfDgramReassembler timedoutReassembler) {
		timedoutReassembler.onTimeoutExpired(datagramQueue);
	}
}
