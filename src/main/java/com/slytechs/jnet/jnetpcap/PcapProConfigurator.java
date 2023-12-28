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
package com.slytechs.jnet.jnetpcap;

import java.util.Objects;
import java.util.function.BooleanSupplier;

import org.jnetpcap.internal.PcapDispatcher;

import com.slytechs.jnet.jnetpcap.PcapPro.PcapProContext;
import com.slytechs.jnet.jnetpcap.internal.PacketReceiver;
import com.slytechs.jnet.jnetpcap.internal.AbstractPacketReceiver.PacketDispatcherFactory;
import com.slytechs.jnet.jnetpcap.internal.AbstractPcapDispatcher.PcapDispatcherFactory;
import com.slytechs.jnet.jnetruntime.util.SystemProperties;

/**
 * Base class for all packet processors.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @param <T> the generic type
 */
public class PcapProConfigurator<T extends PcapProConfigurator<T>> {

	/**
	 * Marker interface for all RX processors which capture/receive packets/data.
	 */
	public interface RxProcessor {

	}

	/**
	 * Marker interface for all TX processor which transmit/save packets/data.
	 */
	public interface TxProcessor {

	}

	/**
	 * A factory for creating Post objects.
	 *
	 * @param <T> the generic type
	 */
	public interface PostRxProcessorFactory<T extends PostRxProcessor> {

		/**
		 * New instance.
		 *
		 * @return the t
		 */
		T newInstance();
	}

	/**
	 * Marker interface for post-processors operate on protocol dissected packets.
	 */
	public interface PostRxProcessor extends RxProcessor {
	}

	/**
	 * A factory for creating Pre objects.
	 *
	 * @param <T> the generic type
	 */
	public interface PreRxProcessorFactory<T extends PreRxProcessor> extends RxProcessor {

		/**
		 * New instance.
		 *
		 * @return the t
		 */
		T newInstance();
	}

	/**
	 * Marker interface for pre-processors which operate on raw native packets.
	 */
	public interface PreRxProcessor extends RxProcessor {
	}

	/** The enable. */
	private boolean enable;

	/** The pcap based factory. */
	private final PcapDispatcherFactory pcapBasedFactory;

	/** The packet based factory. */
	private final PacketDispatcherFactory<T> packetBasedFactory;

	/** The context. */
	private PcapProContext context;

	/**
	 * Instantiates a new pcap pro configurator.
	 *
	 * @param properyPrefix the propery prefix
	 * @param factory       the factory
	 */
	protected PcapProConfigurator(String properyPrefix, PcapDispatcherFactory factory) {
		this.pcapBasedFactory = Objects.requireNonNull(factory, "factory");
		this.packetBasedFactory = null;

		this.enable = SystemProperties.boolValue(properyPrefix + ".enable", true);
	}

	/**
	 * Instantiates a new pcap pro configurator.
	 *
	 * @param properyPrefix the propery prefix
	 * @param factory       the factory
	 */
	protected PcapProConfigurator(String properyPrefix, PacketDispatcherFactory<T> factory) {
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
	 * @param pcapDispatcher the pcap dispatcher
	 * @param context        the context
	 * @return the pcap dispatcher
	 */
	final PcapDispatcher newDispatcherInstance(PcapDispatcher pcapDispatcher, PcapProContext context) {
		return pcapBasedFactory.newInstance(pcapDispatcher, us(), context);
	}

	/**
	 * New dispatcher instance.
	 *
	 * @param pcapDispatcher the pcap dispatcher
	 * @param packetReceiver the packet receiver
	 * @param context        the context
	 * @return the packet receiver
	 */
	final PacketReceiver newDispatcherInstance(PcapDispatcher pcapDispatcher, PacketReceiver packetReceiver,
			PcapProContext context) {
		return packetBasedFactory.newInstance(pcapDispatcher, packetReceiver, us(), context);
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

}
