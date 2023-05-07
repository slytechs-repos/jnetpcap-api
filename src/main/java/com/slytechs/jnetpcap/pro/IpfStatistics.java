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

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public final class IpfStatistics {

	private long tableInsertionFailure;
	private long ipfprocessingFailure;

	/**
	 * 
	 */
	public IpfStatistics() {
	}

	public void incTableInsertionFailure(int delta) {
		tableInsertionFailure += delta;
	}

	public void incIpfProcessingFailure(int delta) {
		ipfprocessingFailure += delta;
	}
}
