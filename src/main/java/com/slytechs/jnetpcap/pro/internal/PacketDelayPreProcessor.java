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

import java.lang.foreign.MemoryAddress;
import java.util.concurrent.TimeUnit;

import org.jnetpcap.internal.PcapDispatcher;

import com.slytechs.jnetpcap.pro.PacketDelay;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class PacketDelayPreProcessor extends AbstractPcapDispatcher implements PcapDispatcher {

	private final PacketDelay config;

	public PacketDelayPreProcessor(PcapDispatcher pcapDispatcher, Object config) {
		super(pcapDispatcher);

		if (!(config instanceof PacketDelay cfg))
			throw new IllegalStateException("Not a PacketPlayer processor");

		this.config = cfg;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.AbstractPcapDispatcher#dispatchNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int dispatchNative(int count, NativeCallback handler, MemoryAddress user) {
		long delayNano = config.getDelay(TimeUnit.NANOSECONDS);

		return super.dispatchNative(count, (MemoryAddress u, MemoryAddress header, MemoryAddress packet) -> {

			handler.nativeCallback(u, header, packet);

			if (delayNano != 0 && delay(delayNano))
				return; // Interrupted

		}, user);
	}

	private boolean delay(long delayNano) {
		try {
			TimeUnit.NANOSECONDS.sleep(delayNano);
		} catch (InterruptedException e) {
			super.interrupt();
			return true;
		}

		return false;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.AbstractPcapDispatcher#loopNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int loopNative(int count, NativeCallback handler, MemoryAddress user) {
		long delayNano = config.getDelay(TimeUnit.NANOSECONDS);

		return super.loopNative(count, (MemoryAddress u, MemoryAddress header, MemoryAddress packet) -> {

			handler.nativeCallback(u, header, packet);

			if (delayNano != 0 && delay(delayNano))
				return; // Interrupted

		}, user);
	}

}
