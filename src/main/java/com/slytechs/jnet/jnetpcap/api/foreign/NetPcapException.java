/*
 * Copyright 2005-2025 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.jnet.jnetpcap.api.foreign;

import java.util.function.Supplier;

import com.slytechs.sdk.common.foreign.ForeignException;
import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.jnetpcap.constant.PcapCode;

/**
 * Checked Pcap errors, warnings and exceptions.
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public class NetPcapException extends PcapException implements ForeignException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = -9051453447740494193L;

	/**
	 * Throw if not ok.
	 *
	 * @param code the code
	 * @throws NetPcapException the pcap exception
	 */
	public static void throwIfNotOk(int code) throws NetPcapException {
		PcapCode status = PcapCode.valueOf(code);
		throwIfNotOk(status, status::getMessage);
	}

	/**
	 * Throw if not ok.
	 *
	 * @param code    the code
	 * @param message the message
	 * @throws NetPcapException the pcap exception
	 */
	public static void throwIfNotOk(int code, Supplier<String> message) throws NetPcapException {
		throwIfNotOk(PcapCode.valueOf(code), message);
	}

	/**
	 * Throw if not ok.
	 *
	 * @param code    the code
	 * @param message the message
	 * @throws NetPcapException the pcap exception
	 */
	public static void throwIfNotOk(PcapCode code, Supplier<String> message) throws NetPcapException {
		if (code.isError()) {
			String msg = message.get();
			throw new NetPcapException(code.getAsInt(), msg.isBlank() ? code.getMessage() : msg);
		}
	}

	/**
	 * Instantiates a new pcap exception.
	 *
	 * @param pcapErrorCode the pcap error code
	 */
	public NetPcapException(int pcapErrorCode) {
		super(pcapErrorCode);
	}

	/**
	 * Instantiates a new pcap exception.
	 *
	 * @param pcapErrorCode the pcap error code
	 * @param message       the message
	 */
	public NetPcapException(int pcapErrorCode, String message) {
		super(pcapErrorCode, message);
	}

	/**
	 * Instantiates a new pcap exception.
	 *
	 * @param pcapErrorCode the pcap error code
	 */
	public NetPcapException(PcapCode pcapErrorCode) {
		super(pcapErrorCode);
	}

	/**
	 * Instantiates a new pcap exception.
	 *
	 * @param message the message
	 */
	public NetPcapException(String message) {
		super(message);
	}
}
