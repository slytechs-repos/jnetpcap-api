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
package com.slytechs.jnetpcap.pro;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;

import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor;
import com.slytechs.jnet.runtime.MemoryBinding;
import com.slytechs.jnet.runtime.time.TimestampUnit;
import com.slytechs.jnet.runtime.util.Detail;

abstract class PacketDescriptorProxy extends PacketDescriptor {

	/**
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.HeaderLookup#isHeaderExtensionSupported()
	 */
	@Override
	public boolean isHeaderExtensionSupported() {
		return getProxy().isHeaderExtensionSupported();
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.HeaderLookup#listHeaders()
	 */
	@Override
	public long[] listHeaders() {
		return getProxy().listHeaders();
	}

	/**
	 * @param id
	 * @param depth
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.HeaderLookup#lookupHeader(int, int)
	 */
	@Override
	public long lookupHeader(int id, int depth) {
		return getProxy().lookupHeader(id, depth);
	}

	/**
	 * @param headerId
	 * @param extId
	 * @param depth
	 * @param recordIndexHint
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.HeaderLookup#lookupHeaderExtension(int,
	 *      int, int, int)
	 */
	@Override
	public long lookupHeaderExtension(int headerId, int extId, int depth, int recordIndexHint) {
		return getProxy().lookupHeaderExtension(headerId, extId, depth, recordIndexHint);
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.runtime.util.StringBuildable#buildString()
	 */
	@Override
	public String buildString() {
		return getProxy().buildString();
	}

	/**
	 * @param detail
	 * @return
	 * @see com.slytechs.jnet.runtime.util.StringBuildable#buildString(com.slytechs.jnet.runtime.util.Detail)
	 */
	@Override
	public String buildString(Detail detail) {
		return getProxy().buildString(detail);
	}

	/**
	 * @return
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return getProxy().hashCode();
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#byteSizeMin()
	 */
	@Override
	public int byteSizeMin() {
		return getProxy().byteSizeMin();
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#byteSizeMax()
	 */
	@Override
	public int byteSizeMax() {
		return getProxy().byteSizeMax();
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#frameNo()
	 */
	@Override
	public long frameNo() {
		return getProxy().frameNo();
	}

	/**
	 * @param newNumber
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#frameNo(long)
	 */
	@Override
	public PacketDescriptor frameNo(long newNumber) {
		return getProxy().frameNo(newNumber);
	}

	/**
	 * @param <T>
	 * @param buffer
	 * @return
	 * @see com.slytechs.jnet.runtime.MemoryBinding#withBinding(java.nio.ByteBuffer)
	 */
	@Override
	public <T> T withBinding(ByteBuffer buffer) {
		return getProxy().withBinding(buffer);
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#byteSize()
	 */
	@Override
	public int byteSize() {
		return getProxy().byteSize();
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#timestamp()
	 */
	@Override
	public long timestamp() {
		return getProxy().timestamp();
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#captureLength()
	 */
	@Override
	public int captureLength() {
		return getProxy().captureLength();
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#wireLength()
	 */
	@Override
	public int wireLength() {
		return getProxy().wireLength();
	}

	/**
	 * @param <T>
	 * @param buffer
	 * @param address
	 * @return
	 * @see com.slytechs.jnet.runtime.MemoryBinding#withBinding(java.nio.ByteBuffer,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public <T> T withBinding(ByteBuffer buffer, MemorySegment address) {
		return getProxy().withBinding(buffer, address);
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#l2FrameType()
	 */
	@Override
	public int l2FrameType() {
		return getProxy().l2FrameType();
	}

	/**
	 * @param obj
	 * @return
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		return getProxy().equals(obj);
	}

	/**
	 * @param timestampUnit
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#timestampUnit(com.slytechs.jnet.runtime.time.TimestampUnit)
	 */
	@Override
	public void timestampUnit(TimestampUnit timestampUnit) {
		getProxy().timestampUnit(timestampUnit);
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.runtime.MemoryBinding#clone()
	 */
	@Override
	public MemoryBinding clone() {
		return getProxy().clone();
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#timestampUnit()
	 */
	@Override
	public TimestampUnit timestampUnit() {
		return getProxy().timestampUnit();
	}

	/**
	 * @param dst
	 * @return
	 * @see com.slytechs.jnet.runtime.MemoryBinding#cloneTo(java.nio.ByteBuffer)
	 */
	@Override
	public MemoryBinding cloneTo(ByteBuffer dst) {
		return getProxy().cloneTo(dst);
	}

	protected PacketDescriptorProxy(PacketDescriptorType type) {
		super(type);
	}

	/**
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#buildDetailedString(java.lang.StringBuilder,
	 *      com.slytechs.jnet.runtime.util.Detail)
	 */
	@Override
	protected StringBuilder buildDetailedString(StringBuilder b, Detail detail) {
		return getProxy().buildString(b, detail);
	}

	/**
	 * @return the proxy
	 */
	abstract PacketDescriptor getProxy();

}