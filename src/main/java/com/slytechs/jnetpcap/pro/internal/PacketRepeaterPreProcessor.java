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

import java.lang.foreign.MemorySegment;
import java.util.concurrent.TimeUnit;

import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnetpcap.pro.PacketRepeater;
import com.slytechs.jnetpcap.pro.PcapPro.PcapProContext;
import com.slytechs.protocol.runtime.time.TimestampUnit;

/**
 * The Class PacketRepeaterPreProcessor.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class PacketRepeaterPreProcessor extends AbstractPcapDispatcher implements PcapDispatcher {

	/** The config. */
	private final PacketRepeater config;
	
	/** The context. */
	private final PcapProContext context;
	
	/** The abi. */
	private final PcapHeaderABI abi;
	
	/** The ts unit. */
	private final TimestampUnit tsUnit;
	
	/** The time unit. */
	private final TimeUnit timeUnit;

	/**
	 * Instantiates a new packet repeater pre processor.
	 *
	 * @param pcapDispatcher the pcap dispatcher
	 * @param config         the config
	 * @param context        the context
	 */
	public PacketRepeaterPreProcessor(PcapDispatcher pcapDispatcher, Object config, PcapProContext context) {
		super(pcapDispatcher);
		this.context = context;

		if (!(config instanceof PacketRepeater cfg))
			throw new IllegalStateException("Not a PacketPlayer processor");

		this.config = cfg;
		this.abi = super.pcapHeaderABI();
		this.tsUnit = cfg.getTimestampUnit();
		this.timeUnit = tsUnit.precisionTimeUnit();
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
	 * Dispatch native.
	 *
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 * @see com.slytechs.jnetpcap.pro.internal.AbstractPcapDispatcher#dispatchNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int dispatchNative(int count, NativeCallback handler, MemorySegment user) {
		long repeatCount = config.getRepeatCount() + 1;
		long delayNano = config.getIfgForRepeated(TimeUnit.NANOSECONDS);
		boolean rewriteTs = config.isRewriteTimestamp();

		return super.dispatchNative(count, (MemorySegment u, MemorySegment header, MemorySegment packet) -> {

			for (long i = 0; i < repeatCount; i++) {

				if ((repeatCount > 1) && rewriteTs && (i > 0))
					rewriteTimestamp(header, delayNano * i);

				handler.nativeCallback(u, header, packet);

				if ((repeatCount > 1) && delayNano > 0 && delay(delayNano))
					return; // Interrupted
			}

		}, user);
	}

	/**
	 * Gets the timestamp nano.
	 *
	 * @param pcapHeader the pcap header
	 * @return the timestamp nano
	 */
	private long getTimestampNano(MemorySegment pcapHeader) {
		long tvSec = abi.tvSec(pcapHeader);
		long tvUsec = abi.tvUsec(pcapHeader);

		long epochTime = tsUnit.ofSecond(tvSec, tvUsec);

		return TimestampUnit.EPOCH_NANO.convert(epochTime, tsUnit);
	}

	/**
	 * Loop native.
	 *
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 * @see com.slytechs.jnetpcap.pro.internal.AbstractPcapDispatcher#loopNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int loopNative(int count, NativeCallback handler, MemorySegment user) {
		long repeatCount = config.getRepeatCount() + 1;
		long delayNano = config.getIfgForRepeated(TimeUnit.NANOSECONDS);
		boolean rewriteTs = config.isRewriteTimestamp();

		return super.loopNative(count, (MemorySegment u, MemorySegment header, MemorySegment packet) -> {

			for (int i = 0; i < repeatCount; i++) {

				if ((repeatCount > 1) && rewriteTs && (i > 0))
					rewriteTimestamp(header, delayNano * i);

				handler.nativeCallback(u, header, packet);

				if ((repeatCount > 1) && (delayNano > 0) && delay(delayNano))
					return; // Interrupted
			}

		}, user);
	}

	/**
	 * Rewrite timestamp.
	 *
	 * @param header       the header
	 * @param incDeltaNano the inc delta nano
	 */
	private void rewriteTimestamp(MemorySegment header, long incDeltaNano) {
		long epochNano = getTimestampNano(header);

		epochNano += incDeltaNano;

		setTimestampNano(header, epochNano);
	}

	/**
	 * Sets the timestamp nano.
	 *
	 * @param pcapHeader the pcap header
	 * @param epochNano  the epoch nano
	 */
	private void setTimestampNano(MemorySegment pcapHeader, long epochNano) {
		long ts = tsUnit.convert(epochNano, TimestampUnit.EPOCH_NANO);
		long tvSec = tsUnit.toEpochSecond(ts);
		long tvUsec = tsUnit.toEpochSecondFraction(ts);

		abi.tvSec(pcapHeader, tvSec);
		abi.tvUsec(pcapHeader, tvUsec);
	}

}
