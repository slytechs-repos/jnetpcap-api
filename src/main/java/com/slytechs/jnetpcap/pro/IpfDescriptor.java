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

import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor;
import com.slytechs.jnet.runtime.util.Detail;

/**
 * A IP fragment tracking descriptor. This descriptor type, tracks IP fragments
 * as they are captured, reassembled and dispatched to program packet handlers.
 * This descriptor is supplied in addition to the regular type descriptors and
 * can forward header lookup calls for protocol resolution.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class IpfDescriptor extends PacketDescriptor {

	/**
	 * @param type
	 */
	public IpfDescriptor(PacketDescriptorType type) {
		super(type);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see com.slytechs.jnet.protocol.packet.HeaderLookup#isHeaderExtensionSupported()
	 */
	@Override
	public boolean isHeaderExtensionSupported() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.packet.HeaderLookup#listHeaders()
	 */
	@Override
	public long[] listHeaders() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.packet.HeaderLookup#lookupHeader(int, int)
	 */
	@Override
	public long lookupHeader(int id, int depth) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.packet.HeaderLookup#lookupHeaderExtension(int,
	 *      int, int, int)
	 */
	@Override
	public long lookupHeaderExtension(int headerId, int extId, int depth, int recordIndexHint) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#byteSize()
	 */
	@Override
	public int byteSize() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#timestamp()
	 */
	@Override
	public long timestamp() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#captureLength()
	 */
	@Override
	public int captureLength() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#wireLength()
	 */
	@Override
	public int wireLength() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.packet.descriptor.PacketDescriptor#buildDetailedString(java.lang.StringBuilder,
	 *      com.slytechs.jnet.runtime.util.Detail)
	 */
	@Override
	protected StringBuilder buildDetailedString(StringBuilder b, Detail detail) {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
