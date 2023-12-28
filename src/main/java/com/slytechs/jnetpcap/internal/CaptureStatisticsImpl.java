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
package com.slytechs.jnetpcap.internal;

import com.slytechs.jnetpcap.CaptureStatistics;

/**
 * The Class CaptureStatisticsImpl.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class CaptureStatisticsImpl implements CaptureStatistics {

	/** The dropped caplen count. */
	long droppedCaplenCount;
	
	/** The dropped packet count. */
	long droppedPacketCount;
	
	/** The dropped wirelen count. */
	long droppedWirelenCount;
	
	/** The received caplen count. */
	long receivedCaplenCount;
	
	/** The received packet count. */
	long receivedPacketCount;
	
	/** The received wirelen count. */
	long receivedWirelenCount;

	/**
	 * Instantiates a new capture statistics impl.
	 */
	public CaptureStatisticsImpl() {
	}

	/**
	 * Gets the dropped caplen count.
	 *
	 * @return the dropped caplen count
	 * @see com.slytechs.jnetpcap.CaptureStatistics#getDroppedCaplenCount()
	 */
	@Override
	public long getDroppedCaplenCount() {
		return droppedCaplenCount;
	}

	/**
	 * Gets the dropped packet count.
	 *
	 * @return the dropped packet count
	 * @see com.slytechs.jnetpcap.CaptureStatistics#getDroppedPacketCount()
	 */
	@Override
	public long getDroppedPacketCount() {
		return droppedPacketCount;
	}

	/**
	 * Gets the dropped wirelen count.
	 *
	 * @return the dropped wirelen count
	 * @see com.slytechs.jnetpcap.CaptureStatistics#getDroppedWirelenCount()
	 */
	@Override
	public long getDroppedWirelenCount() {
		return droppedWirelenCount;
	}

	/**
	 * Gets the received caplen count.
	 *
	 * @return the received caplen count
	 * @see com.slytechs.jnetpcap.CaptureStatistics#getReceivedCaplenCount()
	 */
	@Override
	public long getReceivedCaplenCount() {
		return receivedCaplenCount;
	}

	/**
	 * Gets the received packet count.
	 *
	 * @return the received packet count
	 * @see com.slytechs.jnetpcap.CaptureStatistics#getReceivedPacketCount()
	 */
	@Override
	public long getReceivedPacketCount() {
		return receivedPacketCount;
	}

	/**
	 * Gets the received wirelen count.
	 *
	 * @return the received wirelen count
	 * @see com.slytechs.jnetpcap.CaptureStatistics#getReceivedWirelenCount()
	 */
	@Override
	public long getReceivedWirelenCount() {
		return receivedWirelenCount;
	}

	/**
	 * Inc dropped caplen count.
	 *
	 * @param delta the droppedCaplenCount to inc
	 */
	public void incDroppedCaplenCount(long delta) {
		this.droppedCaplenCount += delta;
	}

	/**
	 * Inc dropped packet count.
	 *
	 * @param delta the droppedPacketCount to inc
	 */
	public void incDroppedPacketCount(long delta) {
		this.droppedPacketCount += delta;
	}

	/**
	 * Inc dropped wirelen count.
	 *
	 * @param delta the droppedWirelenCount to inc
	 */
	public void incDroppedWirelenCount(long delta) {
		this.droppedWirelenCount += delta;
	}

	/**
	 * Inc received caplen count.
	 *
	 * @param delta the receivedCaplenCount to inc
	 */
	public void incReceivedCaplenCount(long delta) {
		this.receivedCaplenCount += delta;
	}

	/**
	 * Inc received packet count.
	 *
	 * @param delta the receivedPacketCount to inc
	 */
	public void incReceivedPacketCount(long delta) {
		this.receivedPacketCount += delta;
	}

	/**
	 * Inc received wirelen count.
	 *
	 * @param delta the receivedWirelenCount to inc
	 */
	public void incReceivedWirelenCount(long delta) {
		this.receivedWirelenCount += delta;
	}

	/**
	 * Inc dropped.
	 *
	 * @param caplen  the caplen
	 * @param wirelen the wirelen
	 * @param packets the packets
	 */
	public void incDropped(int caplen, int wirelen, int packets) {
		droppedCaplenCount += caplen;
		droppedWirelenCount += wirelen;
		droppedPacketCount += packets;
	}

	/**
	 * Inc received.
	 *
	 * @param caplen  the caplen
	 * @param wirelen the wirelen
	 * @param packets the packets
	 */
	public void incReceived(int caplen, int wirelen, int packets) {
		receivedCaplenCount += caplen;
		receivedWirelenCount += wirelen;
		receivedPacketCount += packets;
	}
}
