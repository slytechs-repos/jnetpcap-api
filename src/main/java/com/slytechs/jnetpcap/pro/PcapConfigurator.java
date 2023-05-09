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

import java.util.Objects;
import java.util.function.BooleanSupplier;

import org.jnetpcap.internal.PcapDispatcher;

import com.slytechs.jnetpcap.pro.internal.AbstractPacketDispatcher.PacketDispatcherFactory;
import com.slytechs.jnetpcap.pro.internal.AbstractPcapDispatcher.PcapDispatcherFactory;
import com.slytechs.jnetpcap.pro.internal.PacketDispatcher;
import com.slytechs.protocol.runtime.util.SystemProperties;

/**
 * Base class for all packet processors.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class PcapConfigurator<T extends PcapConfigurator<T>> {

	/**
	 * A factory for creating Post objects.
	 *
	 * @param <T> the generic type
	 */
	public interface PostFactory<T extends PostProcessor> {
		T newInstance();
	}

	/**
	 * Marker interface for post-processors operate on protocol dissected packets.
	 */
	public interface PostProcessor {
	}

	/**
	 * A factory for creating Pre objects.
	 *
	 * @param <T> the generic type
	 */
	public interface PreFactory<T extends PreProcessor> {
		T newInstance();
	}

	/**
	 * Marker interface for pre-processors which operate on raw native packets.
	 */
	public interface PreProcessor {
	}

	private boolean enable;
	private final PcapDispatcherFactory pcapBasedFactory;
	private final PacketDispatcherFactory<T> packetBasedFactory;

	protected PcapConfigurator(String properyPrefix, PcapDispatcherFactory factory) {
		this.pcapBasedFactory = Objects.requireNonNull(factory, "factory");
		this.packetBasedFactory = null;

		this.enable = SystemProperties.boolValue(properyPrefix + ".enable", true);
	}

	protected PcapConfigurator(String properyPrefix, PacketDispatcherFactory<T> factory) {
		this.pcapBasedFactory = null;
		this.packetBasedFactory = Objects.requireNonNull(factory, "factory");;

		this.enable = SystemProperties.boolValue(properyPrefix + ".enable", true);
	}

	public final T enable(boolean enable) {
		boolean oldValue = this.enable;
		this.enable = enable;

		onEnableChange(oldValue, enable);

		return us();
	}

	public final T enableIf(BooleanSupplier predicate) {
		return enable(predicate.getAsBoolean());
	}

	public final boolean isEnabled() {
		return enable;
	}

	final PcapDispatcher newDispatcherInstance(PcapDispatcher pcapDispatcher) {
		return pcapBasedFactory.newInstance(pcapDispatcher, this);
	}

	final PacketDispatcher newDispatcherInstance(PcapDispatcher pcapDispatcher, PacketDispatcher packetDispatcher) {
		return packetBasedFactory.newInstance(pcapDispatcher, packetDispatcher, us());
	}

	protected void onEnableChange(boolean oldValue, boolean newValue) {

	}

	@SuppressWarnings("unchecked")
	protected final T us() {
		return (T) this;
	}

}
