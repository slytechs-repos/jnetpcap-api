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

import java.util.concurrent.TimeUnit;

import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnetpcap.pro.PcapConfigurator.PreProcessor;
import com.slytechs.jnetpcap.pro.internal.PacketPlayerPreProcessor;
import com.slytechs.protocol.runtime.time.TimestampUnit;
import com.slytechs.protocol.runtime.util.SystemProperties;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public class PacketPlayer extends PcapConfigurator<PacketPlayer> implements PreProcessor {

	private static final String PREFIX = "packet.player";
	public static final String PROPERTY_PACKET_PLAYER_ENABLE = PREFIX + ".enable";
	public static final String PROPERTY_PACKET_PLAYER_SYNC = PREFIX + ".sync";
	public static final String PROPERTY_PACKET_PLAYER_SPEED = PREFIX + ".speed";

	private boolean sync = SystemProperties.boolValue(PROPERTY_PACKET_PLAYER_SYNC, true);
	private double speed = SystemProperties.doubleValue(PROPERTY_PACKET_PLAYER_SPEED, 1.0);
	private long referenceTimeNano;
	private TimestampUnit timestampUnit = TimestampUnit.PCAP_MICRO;
	private PcapHeaderABI abi = PcapHeaderABI.selectOfflineAbi(false);

	/**
	 * 
	 */
	public PacketPlayer() {
		super(PREFIX, PacketPlayerPreProcessor::new);
	}

	public PacketPlayer useCurrentTime() {
		setReferenceTime(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

		return this;
	}

	public PacketPlayer setReferenceTimeNano(long timeNano) {
		this.referenceTimeNano = timeNano;

		return this;
	}

	public PacketPlayer setReferenceTime(long time, TimeUnit unit) {
		this.referenceTimeNano = unit.toNanos(time);

		return this;
	}

	public PacketPlayer setTimestampUnit(TimestampUnit unit) {
		this.timestampUnit = unit;

		return this;
	}

	public long getReferenceTimeNano() {
		return referenceTimeNano;
	}

	public PacketPlayer syncOnFirst(boolean sync) {
		this.sync = sync;

		return this;
	}

	public PacketPlayer setSpeed(double speed) {
		if (speed < 0) // Playing backwards not supported
			throw new IllegalArgumentException("negative speed not allowed, playback backwards not supported");

		return this;
	}

	public double getSpeed() {
		return speed;
	}

	public boolean isSync() {
		return sync;
	}

	/**
	 * @return the timestampUnit
	 */
	public TimestampUnit getTimestampUnit() {
		return timestampUnit;
	}

	/**
	 * @return the abi
	 */
	public PcapHeaderABI getAbi() {
		return abi;
	}

	/**
	 * @param abi the abi to set
	 */
	public PacketPlayer setAbi(PcapHeaderABI abi) {
		this.abi = abi;

		return this;
	}
}
