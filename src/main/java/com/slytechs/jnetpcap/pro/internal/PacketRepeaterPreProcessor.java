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
import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnetpcap.pro.PacketRepeater;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public class PacketRepeaterPreProcessor extends AbstractPcapDispatcher implements PcapDispatcher {

	private final PacketRepeater config;
	private final PcapHeaderABI abi;

	public PacketRepeaterPreProcessor(PcapDispatcher pcapDispatcher, Object config) {
		super(pcapDispatcher);

		if (!(config instanceof PacketRepeater cfg))
			throw new IllegalStateException("Not a PacketPlayer processor");

		this.config = cfg;
		this.abi = super.abi();
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.AbstractPcapDispatcher#dispatchNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int dispatchNative(int count, NativeCallback handler, MemoryAddress user) {
		long repeatCount = config.getRepeatCount() + 1;
		long delayNano = config.getDelay(TimeUnit.NANOSECONDS);
		boolean rewriteTs = config.isRewriteTimestamp();

		return super.dispatchNative(count, (MemoryAddress u, MemoryAddress header, MemoryAddress packet) -> {

			for (long i = 0; i < repeatCount; i++) {

				if (repeatCount > 1 && rewriteTs && i > 0)
					rewriteTimestamp(header, delayNano * i);

				handler.nativeCallback(u, header, packet);

				if (repeatCount > 1 && delayNano > 0 && delay(delayNano))
					return; // Interrupted
			}

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

	private void rewriteTimestamp(MemoryAddress header, long incDeltaNano) {

		long tvSec = abi.tvSec(header);
		long tvUsec = abi.tvUsec(header);

		tvUsec += (incDeltaNano / 1000);

		if (tvUsec > 1000000) {
			tvSec++;
			tvUsec -= 1000000;
		}

		rewriteTimestamp(header, tvSec, tvUsec);
	}

	private void rewriteTimestamp(MemoryAddress header, long tvSec, long tvUsec) {
		abi.tvSec(header, tvSec);
		abi.tvUsec(header, tvUsec);
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.AbstractPcapDispatcher#loopNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int loopNative(int count, NativeCallback handler, MemoryAddress user) {
		long repeatCount = config.getRepeatCount() + 1;
		long delayNano = config.getDelay(TimeUnit.NANOSECONDS);
		boolean rewriteTs = config.isRewriteTimestamp();

		return super.loopNative(count, (MemoryAddress u, MemoryAddress header, MemoryAddress packet) -> {

			for (int i = 0; i < repeatCount; i++) {

				if (repeatCount > 1 && rewriteTs && i > 0)
					rewriteTimestamp(header, delayNano * i);

				handler.nativeCallback(u, header, packet);

				if (repeatCount > 1 && delayNano > 0 && delay(delayNano))
					return; // Interrupted
			}

		}, user);
	}

}
