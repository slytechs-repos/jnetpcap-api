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
package com.slytechs.jnetpcap.pro.processor;

import java.util.function.BooleanSupplier;

import com.slytechs.jnetpcap.pro.internal.processor.PushProcesor;
import com.slytechs.jnetpcap.pro.internal.util.Installable;
import com.slytechs.protocol.runtime.util.HasPriority;
import com.slytechs.protocol.runtime.util.SystemProperties;

/**
 * Base interface for all processors.
 */
public abstract class ProProcessor<T_SELF extends ProProcessor<T_SELF>>
		implements HasPriority, Installable {

	private BooleanSupplier enable = () -> true;
	private final String propertyPrefix;
	private final int priority;

	protected ProProcessor(int priority, String propertyPrefix) {
		this.propertyPrefix = propertyPrefix;
		this.priority = priority;
	}

	protected final String prefixProperty(String postfix) {
		return "%s.%s".formatted(this.propertyPrefix, postfix);
	}

	public boolean isEnabled() {
		return SystemProperties.boolValue(prefixProperty("enable"), this.enable.getAsBoolean());
	}

	public T_SELF enable(boolean enable) {
		this.enable = () -> enable;

		return us();
	}

	public T_SELF enableIf(BooleanSupplier enablePredicate) {
		this.enable = enablePredicate;

		return us();
	}

	/**
	 * Us.
	 *
	 * @return the t
	 */
	@SuppressWarnings("unchecked")
	protected final T_SELF us() {
		return (T_SELF) this;
	}

	/**
	 * @see com.slytechs.protocol.runtime.util.HasPriority#priority()
	 */
	@Override
	public int priority() {
		return this.priority;
	}

	public PushProcesor initialize() {
		return newDataProcessorInstance();
	}

	protected abstract PushProcesor newDataProcessorInstance();

}