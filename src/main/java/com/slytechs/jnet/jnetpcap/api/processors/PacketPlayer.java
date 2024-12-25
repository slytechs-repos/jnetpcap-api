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
package com.slytechs.jnet.jnetpcap.api.processors;

import java.lang.foreign.MemorySegment;
import java.util.concurrent.TimeUnit;

import com.slytechs.jnet.jnetpcap.api.internal.PrePcapPipeline.PreContext;
import com.slytechs.jnet.jnetpcap.api.processors.PreProcessors.PreProcessor;
import com.slytechs.jnet.platform.api.data.common.processor.Processor;
import com.slytechs.jnet.platform.api.util.time.TimestampUnit;

/**
 * The Class PacketPlayer.
 *
 * @author Mark Bednarczyk
 */
public class PacketPlayer
		extends Processor<PreProcessor>
		implements PreProcessor {

	private PacketPlayerSettings settings = new PacketPlayerSettings();
	{
		// Link settings to certain actions
		settings.ENABLE.on(newValue -> setEnable(newValue));
	}

	private long referenceTimeNano;

	/** The Constant NAME. */
	public static final String NAME = "PacketPlayer";

	/**
	 * Instantiates a new packet player.
	 *
	 * @param pipeline the pipeline
	 * @param priority the priority
	 */
	public PacketPlayer() {
		super(PreProcessors.PACKET_PLAYER_PRIORITY, NAME);
	}

	/**
	 * Instantiates a new packet player.
	 *
	 * @param pipeline the pipeline
	 * @param priority the priority
	 */
	public PacketPlayer(PacketPlayerSettings settings) {
		super(PreProcessors.PACKET_PLAYER_PRIORITY, NAME);

		this.settings.mergeValues(settings);
	}

	/**
	 * Use current time.
	 *
	 * @return the packet player
	 */
	public PacketPlayer useCurrentTime() {
		rwGuard.writeLocked(() -> setReferenceTime(System.currentTimeMillis(), TimeUnit.MILLISECONDS));

		return this;
	}

	/**
	 * Sets the reference time nano.
	 *
	 * @param timeNano the time nano
	 * @return the packet player
	 */
	public PacketPlayer setReferenceTimeNano(long timeNano) {
		rwGuard.writeLocked(() -> this.referenceTimeNano = timeNano);

		return this;
	}

	/**
	 * Sets the reference time.
	 *
	 * @param time the time
	 * @param unit the unit
	 * @return the packet player
	 */
	public PacketPlayer setReferenceTime(long time, TimeUnit unit) {
		rwGuard.writeLocked(() -> this.referenceTimeNano = unit.toNanos(time));

		return this;
	}

	/**
	 * Sets the timestamp unit.
	 *
	 * @param unit the unit
	 * @return the packet player
	 */
	public PacketPlayer setTimestampUnit(TimestampUnit unit) {
		rwGuard.writeLocked(() -> settings.TS_UNIT.setValue(unit, PacketPlayer.this));

		return this;
	}

	/**
	 * Gets the reference time nano.
	 *
	 * @return the reference time nano
	 */
	public long getReferenceTimeNano() {
		return rwGuard.readLocked(() -> referenceTimeNano);
	}

	/**
	 * Sync timestamp.
	 *
	 * @param sync the sync
	 * @return the packet player
	 */
	public PacketPlayer syncTimestamp(boolean sync) {
		rwGuard.writeLocked(() -> settings.SYNC.setValue(sync, PacketPlayer.this));

		return this;
	}

	/**
	 * Preserve ifg.
	 *
	 * @param sync the sync
	 * @return the packet player
	 */
	public PacketPlayer preserveIfg(boolean sync) {
		rwGuard.writeLocked(() -> settings.IFG_PRESERVE.setValue(sync, PacketPlayer.this));

		return this;
	}

	/**
	 * Sets the min ifg.
	 *
	 * @param duration the duration
	 * @param unit     the unit
	 * @return the packet player
	 */
	public PacketPlayer setMinIfg(long duration, TimeUnit unit) {
		rwGuard.writeLocked(() -> settings.IFG_MIN.setValue(unit.toNanos(duration), PacketPlayer.this));
		return this;
	}

	/**
	 * Sets the max ifg.
	 *
	 * @param duration the duration
	 * @param unit     the unit
	 * @return the packet player
	 */
	public PacketPlayer setMaxIfg(long duration, TimeUnit unit) {
		rwGuard.writeLocked(() -> settings.IFG_MAX.setValue(unit.toNanos(duration), PacketPlayer.this));

		return this;
	}

	public boolean hasRewriteTimestamp() {
		return rwGuard.readLocked(() -> settings.REWRITE_TIMESTAMP.getBoolean());
	}

	public PacketPlayer setRewriteTimestamp(boolean state) {
		rwGuard.writeLocked(() -> settings.REWRITE_TIMESTAMP.setValue(state, PacketPlayer.this));

		return this;
	}

	/**
	 * Play.
	 *
	 * @param speed the speed
	 * @return the packet player
	 */
	public PacketPlayer setSpeed(double speed) throws IllegalArgumentException {

		rwGuard.writeLocked(() -> {
			if (speed < 0) // Playing backwards not supported
				throw new IllegalArgumentException("negative speed not allowed, playback backwards not supported");

			settings.SPEED.setValue(speed, this);

			return null;
		}, IllegalArgumentException.class);

		return this;

	}

	/**
	 * Gets the speed.
	 *
	 * @return the speed
	 */
	public double getSpeed() {
		return rwGuard.readLocked(() -> settings.SPEED.getDouble());
	}

	/**
	 * Checks if is sync.
	 *
	 * @return true, if is sync
	 */
	public boolean isSync() {
		return rwGuard.readLocked(() -> settings.SYNC.getBoolean());
	}

	/**
	 * Gets the timestamp unit.
	 *
	 * @return the timestampUnit
	 */
	public TimestampUnit getTimestampUnit() {
		return rwGuard.readLocked(() -> settings.TS_UNIT.getEnum());
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.api.processors.PreProcessors.PreProcessor#preProcessPacket(java.lang.foreign.MemorySegment,
	 *      java.lang.foreign.MemorySegment,
	 *      com.slytechs.jnet.jnetpcap.api.internal.PrePcapPipeline.PreContext)
	 */
	@Override
	public long preProcessPacket(MemorySegment header, MemorySegment packet,
			@SuppressWarnings("exports") PreContext ctx) {

		try {

			boolean rewrite = settings.REWRITE_TIMESTAMP.getBoolean();
			long ifg = settings.IFG.toOptionalLong().orElse(0);
			double speed = settings.SPEED.getDouble();

			var stopWatch = ctx.frameStopwatch;
			var frameHdr = ctx.pcapHeader;

			if (ifg > 0)
				stopWatch.delayIfg((long) (ifg * speed));

			if (rewrite && ifg > 0)
				frameHdr.timestamp(stopWatch.newTsNanos(), TimestampUnit.EPOCH_NANO);

			return getOutput().preProcessPacket(header, packet, ctx);

		} catch (InterruptedException e) {
			handleError(e, this);

			return 0;
		}

	}

}
