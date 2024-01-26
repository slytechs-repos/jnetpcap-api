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
package com.slytechs.jnet.jnetpcap.processor;

import java.util.function.BooleanSupplier;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public interface Processor extends Comparable<Processor> {

	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	default int compareTo(Processor o) {
		return priority() - o.priority();
	}

	String name();

	Processor name(String newName);

	int priority();

	ProcessorType type();

	boolean isEnabled();

	Processor enable(BooleanSupplier b);

	Processor enable(boolean b);
}
