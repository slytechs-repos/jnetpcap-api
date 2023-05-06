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

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public class PacketStatisticsImpl implements PacketStatistics {

	long droppedCaplenCount;
	long droppedPacketCount;
	long droppedWirelenCount;
	long receivedCaplenCount;
	long receivedPacketCount;
	long receivedWirelenCount;

	/**
	 * 
	 */
	public PacketStatisticsImpl() {
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.PacketStatistics#getDroppedCaplenCount()
	 */
	@Override
	public long getDroppedCaplenCount() {
		return droppedCaplenCount;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.PacketStatistics#getDroppedPacketCount()
	 */
	@Override
	public long getDroppedPacketCount() {
		return droppedPacketCount;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.PacketStatistics#getDroppedWirelenCount()
	 */
	@Override
	public long getDroppedWirelenCount() {
		return droppedWirelenCount;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.PacketStatistics#getReceivedCaplenCount()
	 */
	@Override
	public long getReceivedCaplenCount() {
		return receivedCaplenCount;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.PacketStatistics#getReceivedPacketCount()
	 */
	@Override
	public long getReceivedPacketCount() {
		return receivedPacketCount;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.PacketStatistics#getReceivedWirelenCount()
	 */
	@Override
	public long getReceivedWirelenCount() {
		return receivedWirelenCount;
	}

	/**
	 * @param delta the droppedCaplenCount to inc
	 */
	public void incDroppedCaplenCount(long delta) {
		this.droppedCaplenCount += delta;
	}

	/**
	 * @param delta the droppedPacketCount to inc
	 */
	public void incDroppedPacketCount(long delta) {
		this.droppedPacketCount += delta;
	}

	/**
	 * @param delta the droppedWirelenCount to inc
	 */
	public void incDroppedWirelenCount(long delta) {
		this.droppedWirelenCount += delta;
	}

	/**
	 * @param delta the receivedCaplenCount to inc
	 */
	public void incReceivedCaplenCount(long delta) {
		this.receivedCaplenCount += delta;
	}

	/**
	 * @param delta the receivedPacketCount to inc
	 */
	public void incReceivedPacketCount(long delta) {
		this.receivedPacketCount += delta;
	}

	/**
	 * @param delta the receivedWirelenCount to inc
	 */
	public void incReceivedWirelenCount(long delta) {
		this.receivedWirelenCount += delta;
	}

	public void incDropped(int caplen, int wirelen, int packets) {
		droppedCaplenCount += caplen;
		droppedWirelenCount += wirelen;
		droppedPacketCount += packets;
	}

	public void incReceived(int caplen, int wirelen, int packets) {
		receivedCaplenCount += caplen;
		receivedWirelenCount += wirelen;
		receivedPacketCount += packets;
	}
}
