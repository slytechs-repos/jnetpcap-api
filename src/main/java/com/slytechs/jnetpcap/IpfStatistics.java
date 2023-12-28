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
package com.slytechs.jnetpcap;

/**
 * The Class IpfStatistics.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public final class IpfStatistics {

	/** The table insertion failure. */
	private long tableInsertionFailure;
	
	/** The ipfprocessing failure. */
	private long ipfprocessingFailure;

	/**
	 * Instantiates a new ipf statistics.
	 */
	public IpfStatistics() {
	}

	/**
	 * Inc table insertion failure.
	 *
	 * @param delta the delta
	 */
	public void incTableInsertionFailure(int delta) {
		tableInsertionFailure += delta;
	}

	/**
	 * Inc ipf processing failure.
	 *
	 * @param delta the delta
	 */
	public void incIpfProcessingFailure(int delta) {
		ipfprocessingFailure += delta;
	}
}
