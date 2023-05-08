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

import com.slytechs.jnetpcap.pro.internal.CaptureStatisticsImpl;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public interface CaptureStatistics {

	public static CaptureStatistics newInstance() {
		return new CaptureStatisticsImpl();
	}

	/**
	 * Number of bytes that were dropped due to errors while receiving packets. If
	 * byte count for any packet received and dropped is not available, the counter
	 * will not reflect that correct value.
	 * 
	 * @return 64-bit counter
	 */
	long getDroppedCaplenCount();

	/**
	 * Number of packets that have been dropped due to errors when receiving
	 * packets.
	 * 
	 * @return 64-bit counter
	 */
	long getDroppedPacketCount();

	/**
	 * Number of bytes seen on the wire that were dropped due to errors while
	 * receiving packets. If byte count for any packet seen on wire and dropped is
	 * not available, the counter will not reflect that correct value.
	 * 
	 * @return 64-bit counter
	 */
	long getDroppedWirelenCount();

	/**
	 * Number of total bytes received since the start of the pcap capture.
	 * 
	 * @return a 64-bit counter in units of bytes
	 */
	long getReceivedCaplenCount();

	/**
	 * Number of packets received since that start of the pcap capture.
	 * 
	 * @return a 64-bit counter
	 */
	long getReceivedPacketCount();

	/**
	 * Number of total bytes seen on the wire since the start of the pcap capture.
	 * 
	 * @return a 64-bit counter in units of bytes
	 */
	long getReceivedWirelenCount();
}
