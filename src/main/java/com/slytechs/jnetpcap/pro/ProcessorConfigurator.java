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

import org.jnetpcap.internal.PacketDispatcher;

import com.slytechs.jnetpcap.pro.PcapPro.PcapProContext;
import com.slytechs.jnetpcap.pro.internal.AbstractPacketReceiver.PacketDispatcherFactory;
import com.slytechs.jnetpcap.pro.internal.AbstractPcapDispatcher.PcapDispatcherFactory;
import com.slytechs.jnetpcap.pro.internal.PacketReceiver;
import com.slytechs.protocol.runtime.util.HasPriority;
import com.slytechs.protocol.runtime.util.SystemProperties;

/**
 * Base class for all packet processors.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @param <T> the generic type
 */
public class ProcessorConfigurator<T extends ProcessorConfigurator<T>> implements HasPriority {

	/** The enable. */
	private boolean enable;

	/** The pcap based factory. */
	private final PcapDispatcherFactory pcapBasedFactory;

	/** The packet based factory. */
	private final PacketDispatcherFactory<T> packetBasedFactory;

	/** The context. */
	private PcapProContext context;

	private final int priority;

	/**
	 * Instantiates a new pcap pro configurator.
	 * @param priority TODO
	 * @param properyPrefix the propery prefix
	 * @param factory       the factory
	 */
	protected ProcessorConfigurator(int priority, String properyPrefix, PcapDispatcherFactory factory) {
		this.priority = priority;
		this.pcapBasedFactory = Objects.requireNonNull(factory, "factory");
		this.packetBasedFactory = null;

		this.enable = SystemProperties.boolValue(properyPrefix + ".enable", true);
	}

	/**
	 * Instantiates a new pcap pro configurator.
	 * @param priority TODO
	 * @param properyPrefix the propery prefix
	 * @param factory       the factory
	 */
	protected ProcessorConfigurator(int priority, String properyPrefix, PacketDispatcherFactory<T> factory) {
		this.priority = priority;
		this.pcapBasedFactory = null;
		this.packetBasedFactory = Objects.requireNonNull(factory, "factory");

		this.enable = SystemProperties.boolValue(properyPrefix + ".enable", true);
	}

	/**
	 * Enable.
	 *
	 * @param enable the enable
	 * @return the t
	 */
	public final T enable(boolean enable) {
		boolean oldValue = this.enable;
		this.enable = enable;

		onEnableChange(oldValue, enable);

		return us();
	}

	/**
	 * Enable if.
	 *
	 * @param predicate the predicate
	 * @return the t
	 */
	public final T enableIf(BooleanSupplier predicate) {
		return enable(predicate.getAsBoolean());
	}

	/**
	 * Checks if is enabled.
	 *
	 * @return true, if is enabled
	 */
	public final boolean isEnabled() {
		return enable;
	}

	/**
	 * New dispatcher instance.
	 *
	 * @param packetDispatcher the pcap dispatcher
	 * @param context        the context
	 * @return the pcap dispatcher
	 */
	public final PacketDispatcher newDispatcherInstance(PacketDispatcher packetDispatcher, PcapProContext context) {
		return pcapBasedFactory.newInstance(packetDispatcher, us(), context);
	}

	/**
	 * New dispatcher instance.
	 *
	 * @param packetDispatcher the pcap dispatcher
	 * @param packetReceiver the packet receiver
	 * @param context        the context
	 * @return the packet receiver
	 */
	public final PacketReceiver newDispatcherInstance(PacketDispatcher packetDispatcher, PacketReceiver packetReceiver,
			PcapProContext context) {
		return packetBasedFactory.newInstance(packetDispatcher, packetReceiver, us(), context);
	}

	/**
	 * On enable change.
	 *
	 * @param oldValue the old value
	 * @param newValue the new value
	 */
	protected void onEnableChange(boolean oldValue, boolean newValue) {

	}

	/**
	 * Gets the pcap context.
	 *
	 * @return the pcap context
	 */
	public final PcapProContext getPcapContext() {
		return this.context;
	}

	/**
	 * Us.
	 *
	 * @return the t
	 */
	@SuppressWarnings("unchecked")
	protected final T us() {
		return (T) this;
	}

	/**
	 * @see com.slytechs.protocol.runtime.util.HasPriority#priority()
	 */
	@Override
	public int priority() {
		throw new UnsupportedOperationException("not implemented yet");
	}
}
