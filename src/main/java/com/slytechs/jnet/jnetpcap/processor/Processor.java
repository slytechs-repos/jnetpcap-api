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

import java.util.function.BooleanSupplier;

/**
 * The Interface Processor.
 *
 * @author Mark Bednarczyk
 */
public interface Processor extends Comparable<Processor> {

	/**
	 * Compare to.
	 *
	 * @param o the o
	 * @return the int
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	default int compareTo(Processor o) {
		return priority() - o.priority();
	}

	/**
	 * Name.
	 *
	 * @return the string
	 */
	String name();

	/**
	 * Name.
	 *
	 * @param newName the new name
	 * @return the processor
	 */
	Processor name(String newName);

	/**
	 * Priority.
	 *
	 * @return the int
	 */
	int priority();

	/**
	 * Type.
	 *
	 * @return the processor type
	 */
	ProcessorType type();

	/**
	 * Checks if is enabled.
	 *
	 * @return true, if is enabled
	 */
	boolean isEnabled();

	/**
	 * Enable.
	 *
	 * @param b the b
	 * @return the processor
	 */
	Processor enable(BooleanSupplier b);

	/**
	 * Enable.
	 *
	 * @param b the b
	 * @return the processor
	 */
	Processor enable(boolean b);
}
