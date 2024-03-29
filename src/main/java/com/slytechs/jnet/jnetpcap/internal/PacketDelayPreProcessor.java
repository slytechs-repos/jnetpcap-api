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
package com.slytechs.jnet.jnetpcap.internal;

import java.lang.foreign.MemorySegment;
import java.util.concurrent.TimeUnit;

import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.internal.PcapDispatcher;

import com.slytechs.jnet.jnetpcap.PacketDelay;
import com.slytechs.jnet.jnetpcap.NetPcap.PcapProContext;

/**
 * The Class PacketDelayPreProcessor.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class PacketDelayPreProcessor extends AbstractPcapDispatcher implements PcapDispatcher {

	/** The config. */
	private final PacketDelay config;
	
	/** The context. */
	private final PcapProContext context;

	/**
	 * Instantiates a new packet delay pre processor.
	 *
	 * @param pcapDispatcher the pcap dispatcher
	 * @param config         the config
	 * @param context        the context
	 */
	public PacketDelayPreProcessor(PcapDispatcher pcapDispatcher, Object config, PcapProContext context) {
		super(pcapDispatcher);
		this.context = context;

		if (!(config instanceof PacketDelay cfg))
			throw new IllegalStateException("Not a PacketPlayer processor");

		this.config = cfg;
	}

	/**
	 * Dispatch native.
	 *
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 * @see com.slytechs.jnet.jnetpcap.internal.AbstractPcapDispatcher#dispatchNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int dispatchNative(int count, NativeCallback handler, MemorySegment user) {
		long delayNano = config.getDelay(TimeUnit.NANOSECONDS);

		return super.dispatchNative(count, (MemorySegment u, MemorySegment header, MemorySegment packet) -> {

			handler.nativeCallback(u, header, packet);

			if (delayNano != 0 && delay(delayNano))
				return; // Interrupted

		}, user);
	}

	/**
	 * Delay.
	 *
	 * @param delayNano the delay nano
	 * @return true, if successful
	 */
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
	 * Loop native.
	 *
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 * @see com.slytechs.jnet.jnetpcap.internal.AbstractPcapDispatcher#loopNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int loopNative(int count, NativeCallback handler, MemorySegment user) {
		long delayNano = config.getDelay(TimeUnit.NANOSECONDS);

		return super.loopNative(count, (MemorySegment u, MemorySegment header, MemorySegment packet) -> {

			handler.nativeCallback(u, header, packet);

			if (delayNano != 0 && delay(delayNano))
				return; // Interrupted

		}, user);
	}

}
