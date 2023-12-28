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
package com.slytechs.jnet.jnetpcap.internal;

import org.jnetpcap.internal.PcapDispatcher;

/**
 * The Class ProxyPreProcessor.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class ProxyPreProcessor extends AbstractPcapDispatcher {

	/** The dispatcher. */
	private PcapDispatcher dispatcher;

	/**
	 * Instantiates a new proxy pre processor.
	 */
	public ProxyPreProcessor() {
	}

	/**
	 * Gets the pcap dispatcher.
	 *
	 * @return the pcap dispatcher
	 * @see com.slytechs.jnet.jnetpcap.internal.AbstractPcapDispatcher#getPcapDispatcher()
	 */
	@Override
	protected PcapDispatcher getPcapDispatcher() {
		return dispatcher;
	}

	/**
	 * Sets the dispatcher.
	 *
	 * @param dispatcher the new dispatcher
	 */
	public void setDispatcher(PcapDispatcher dispatcher) {
		this.dispatcher = dispatcher;
	}
}
