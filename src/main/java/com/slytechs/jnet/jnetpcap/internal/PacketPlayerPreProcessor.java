/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnet.jnetpcap.PacketPlayer;
import com.slytechs.jnet.jnetpcap.NetPcap.NetPcapContext;
import com.slytechs.jnet.jnetruntime.time.TimeSource;
import com.slytechs.jnet.jnetruntime.time.TimestampUnit;

/**
 * The Class PacketPlayerPreProcessor.
 *
 * @author Mark Bednarczyk
 */
public class PacketPlayerPreProcessor extends AbstractPcapDispatcher implements PcapDispatcher {

	/** The context. */
	private final NetPcapContext context;
	
	/** The config. */
	private final PacketPlayer config;

	/** The initialized. */
	private boolean initialized;
	
	/** The reference time nano. */
	private long referenceTimeNano;
	
	/** The speed. */
	private double speed;

	/** The timestamp unit. */
	private TimestampUnit timestampUnit;

	/** The abi. */
	private PcapHeaderABI abi;
	
	/** The time source. */
	private final TimeSource.Updatable timeSource;

	/**
	 * Instantiates a new packet player pre processor.
	 *
	 * @param pcapDispatcher the pcap dispatcher
	 * @param config         the config
	 * @param context        the context
	 */
	public PacketPlayerPreProcessor(PcapDispatcher pcapDispatcher, Object config, NetPcapContext context) {
		super(pcapDispatcher);

		if (!(config instanceof PacketPlayer cfg))
			throw new IllegalStateException("Not a PacketPlayer processor");

		this.config = cfg;
		this.context = context;
		this.timeSource = Objects.requireNonNull(context.getTimeSource(), "PcapProContext.timeSource")
				.asUpdatable()
				.orElseThrow(() -> new IllegalStateException(
						"invalid time source for Player type processor [%s]"
								.formatted(context.getTimeSource().getClass())));
	}

	/**
	 * Preserve ifg.
	 *
	 * @return the packet player pre processor
	 */
	public PacketPlayerPreProcessor preserveIfg() {
		return this;
	}

	/**
	 * Initialize.
	 */
	private void initialize() {
		initialized = true;

		this.referenceTimeNano = config.getReferenceTimeNano();
		this.timestampUnit = config.getTimestampUnit();
		this.speed = config.getSpeed();
		this.abi = config.getAbi();
	}

	/**
	 * Dispatch native.
	 *
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 * @see com.slytechs.jnet.jnetpcap.internal.AbstractPcapDispatcher#invokeDispatchNativeCallback(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int invokeDispatchNativeCallback(int count, NativeCallback handler, MemorySegment user) {
		if (initialized == false)
			initialize();

		return super.invokeDispatchNativeCallback(count, (MemorySegment u, MemorySegment header, MemorySegment packet) -> {

			if (referenceTimeNano == 0)
				referenceTimeNano = getTimestampNano(header);

			long tsNano = getTimestampNano(header);
			long delayNano = tsNano - referenceTimeNano;
			delayNano = (long) (delayNano / speed);

			delay(delayNano);

			handler.nativeCallback(u, header, packet);

//			System.out.printf("ref=%d, tsNano=%d, delay=%dns, %s%n",
//					referenceTimeNano, tsNano, delayNano,
//					new Timestamp(tsNano, TimestampUnit.EPOCH_NANO));

		}, user);
	}

	/**
	 * Delay.
	 *
	 * @param delayNano the delay nano
	 * @return true, if successful
	 */
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
	 * Gets the timestamp nano.
	 *
	 * @param header the header
	 * @return the timestamp nano
	 */
	private long getTimestampNano(MemorySegment header) {
		long tvSec = abi.tvSec(header);
		long tvUsec = abi.tvUsec(header);

		long ts = timestampUnit.ofSecond(tvSec, tvUsec);

		return TimestampUnit.EPOCH_NANO.convert(ts, timestampUnit);
	}
}
