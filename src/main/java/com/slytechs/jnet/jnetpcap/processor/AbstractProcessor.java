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
public abstract class AbstractProcessor<T extends Processor> implements Processor {

	private final int priority;
	private String name;
	private final ProcessorType type;

	private BooleanSupplier enabled;

	protected AbstractProcessor(ProcessorType type, int priority) {
		this.type = type;
		this.priority = priority;
		this.name = getClass().getSimpleName();
	}

	protected AbstractProcessor(ProcessorType type, int priority, String name) {
		this.type = type;
		this.priority = priority;
		this.name = getClass().getSimpleName();
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.processor.Processor#name(java.lang.String)
	 */
	@Override
	public T name(String newName) {
		name = newName;

		return us();
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.processor.Processor#priority()
	 */
	@Override
	public int priority() {
		return priority;
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.processor.Processor#name()
	 */
	@Override
	public String name() {
		return name;
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.processor.Processor#type()
	 */
	@Override
	public ProcessorType type() {
		return type;
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.processor.Processor#isEnabled()
	 */
	@Override
	public boolean isEnabled() {
		return enabled.getAsBoolean();
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.processor.Processor#enable(java.util.function.BooleanSupplier)
	 */
	@Override
	public T enable(BooleanSupplier b) {
		this.enabled = b;

		return us();
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.processor.Processor#enable(boolean)
	 */
	@Override
	public T enable(boolean b) {
		return enable(() -> b);
	}

	@SuppressWarnings("unchecked")
	protected T us() {
		return (T) this;
	}

}
