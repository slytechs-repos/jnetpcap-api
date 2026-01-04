/*
 * Copyright 2005-2025 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.jnet.jnetpcap.api.foreign;

import java.lang.foreign.MemorySegment;

import com.slytechs.sdk.jnetpcap.internal.PcapHeaderABI;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class UserUpcall implements NativeUpcall {
	private NativeUpcall userCallback;

	private final PcapHeaderABI abi;

	public UserUpcall(PcapHeaderABI abi) {
		this.abi = abi;
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.api.foreign.NativeUpcall#nativeUpcall(java.lang.foreign.MemorySegment,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public void nativeUpcall(MemorySegment user, MemorySegment header, MemorySegment packet) {

		try {

			int hdrlen = abi.headerLength();
			header = header.reinterpret(hdrlen);

			int caplen = abi.captureLength(header);
			packet = packet.reinterpret(caplen);

			this.userCallback.nativeUpcall(user, header, packet);
		} catch (RuntimeException e) {}
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.api.foreign.NativeUpcall#setUserCallback(com.slytechs.jnet.jnetpcap.api.foreign.ScopedCallback)
	 */
	@Override
	public void setUserCallback(NativeUpcall userCallback) {
		this.userCallback = userCallback;
	}
}
