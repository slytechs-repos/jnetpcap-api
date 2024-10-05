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
package com.slytechs.jnet.jnetpcap.processor;

import org.jnetpcap.PcapException;

/**
 * The Interface ProcessorConfig.
 *
 * @author Mark Bednarczyk
 */
public interface ProcessorConfig extends AutoCloseable {

	/**
	 * New instance.
	 *
	 * @return the processor config
	 */
	static ProcessorConfig newInstance() {
		throw new UnsupportedOperationException();
	}

	/**
	 * Install.
	 *
	 * @param <T>     the generic type
	 * @param factory the factory
	 * @return the t
	 */
	<T extends Processor> T install(ProcessorFactory<T> factory);

	/**
	 * Install.
	 *
	 * @param <T>      the generic type
	 * @param priority the priority
	 * @param factory  the factory
	 * @return the t
	 */
	<T extends Processor> T install(int priority, ProcessorFactory<T> factory);

	/**
	 * @see java.lang.AutoCloseable#close()
	 */
	@Override
	default void close() throws PcapException {
		activate();
	}

	/**
	 * Activate.
	 *
	 * @throws PcapException the pcap exception
	 */
	void activate() throws PcapException;
}