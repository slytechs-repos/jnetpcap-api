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

import com.slytechs.jnetpcap.pro.PacketPlayer;
import com.slytechs.protocol.runtime.time.Timestamp;
import com.slytechs.protocol.runtime.time.TimestampUnit;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class PacketPlayerPreProcessor extends AbstractPcapDispatcher implements PcapDispatcher {

	private final PacketPlayer config;

	private boolean initialized;
	private long referenceTimeNano;
	private double speed;

	private TimestampUnit timestampUnit;

	private PcapHeaderABI abi;

	public PacketPlayerPreProcessor(PcapDispatcher pcapDispatcher, Object config) {
		super(pcapDispatcher);

		if (!(config instanceof PacketPlayer cfg))
			throw new IllegalStateException("Not a PacketPlayer processor");

		this.config = cfg;
	}

	public PacketPlayerPreProcessor syncOnFirst() {
		return this;
	}

	private void initialize() {
		initialized = true;

		this.referenceTimeNano = config.getReferenceTimeNano();
		this.timestampUnit = config.getTimestampUnit();
		this.speed = config.getSpeed();
		this.abi = config.getAbi();
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.AbstractPcapDispatcher#dispatchNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int dispatchNative(int count, NativeCallback handler, MemoryAddress user) {
		if (initialized == false)
			initialize();

		return super.dispatchNative(count, (MemoryAddress u, MemoryAddress header, MemoryAddress packet) -> {

			if (referenceTimeNano == 0)
				referenceTimeNano = getTimestampNano(header);

			long tsNano = getTimestampNano(header);
			long delayNano = tsNano - referenceTimeNano;
			delayNano = (long) (delayNano / speed);

			delay(delayNano);

			handler.nativeCallback(u, header, packet);

			System.out.printf("ref=%d, tsNano=%d, delay=%dns, %s%n",
					referenceTimeNano, tsNano, delayNano,
					new Timestamp(tsNano, TimestampUnit.EPOCH_NANO));

		}, user);
	}

	private boolean delay(long delayNano) {
		if (delayNano <= 0)
			return false;

		try {
			TimeUnit.NANOSECONDS.sleep(delayNano);
		} catch (InterruptedException e) {
			super.interrupt();
			return true;
		}

		return false;
	}

	/**
	 * @param header
	 * @return
	 */
	private long getTimestampNano(MemoryAddress header) {
		long tvSec = abi.tvSec(header);
		long tvUsec = abi.tvUsec(header);

		long ts = timestampUnit.ofSecond(tvSec, tvUsec);

		return TimestampUnit.EPOCH_NANO.convert(ts, timestampUnit);
	}
}
