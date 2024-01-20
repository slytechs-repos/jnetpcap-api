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
package com.slytechs.jnet.jnetpcap;

/**
 * The type of pcap handle that is open by an instance of pcap-pro. Provides
 * several boolean getter methods for positive and negative (opposite) checks on
 * specific pcap types for ease of use in lambda expressions.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public enum PcapType {

	/** A live capture from a network device. */
	LIVE_CAPTURE,

	/** An offline file reader. */
	OFFLINE_READER,

	/**
	 * A dead handle used for BPF filtering and certain packet processor usage.
	 */
	DEAD_HANDLE,

	;

	/**
	 * Checks if is dead handle.
	 *
	 * @return true, if is dead
	 */
	public boolean isDead() {
		return (this == DEAD_HANDLE);
	}

	/**
	 * Checks if is live capture.
	 *
	 * @return true, if is live
	 */
	public boolean isLive() {
		return (this == LIVE_CAPTURE);
	}

	/**
	 * Checks if is not dead handle.
	 *
	 * @return true, if is not dead
	 */
	public boolean isNotDead() {
		return !isDead();
	}

	/**
	 * Checks if is not live capture.
	 *
	 * @return true, if is not live
	 */
	public boolean isNotLive() {
		return !isLive();
	}

	/**
	 * Checks if is not offline reader.
	 *
	 * @return true, if is not offline
	 */
	public boolean isNotOffline() {
		return !isOffline();
	}

	/**
	 * Checks if is offline reader.
	 *
	 * @return true, if is offline
	 */
	public boolean isOffline() {
		return (this == OFFLINE_READER);
	}
}
