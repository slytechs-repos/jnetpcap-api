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

import org.jnetpcap.internal.PcapDispatcher;

import com.slytechs.jnetpcap.pro.PacketProcessor.PreProcessor.PreInstaller;
import com.slytechs.jnetpcap.pro.internal.AbstractPreProcessor.PcapDispatcherFactory;
import com.slytechs.protocol.runtime.util.SystemProperties;

/**
 * Base class for all packet processors.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class PacketProcessor<T extends PacketProcessor<T>> {

	/**
	 * Marker interface for pre-processors which operate on raw native packets.
	 */
	public interface PreProcessor {
		public interface PreFactory<T extends PreProcessor> {
			T newInstance(PreInstaller installer);
		}

		public interface PreInstaller {
			void install(PreProcessor newProcessor);
		}

	}

	/**
	 * Marker interface for post-processors operate on protocol dissected packets.
	 */
	public interface PostProcessor {
		public interface PostFactory<T extends PostProcessor> {
			T newInstance(PostInstaller installer);
		}

		public interface PostInstaller {
			void install(PostProcessor newProcessor);
		}

	}

	private boolean enable;
	private final PcapDispatcherFactory factory;
	private final PreInstaller installer;

	protected PacketProcessor(String properyPrefix, PcapDispatcherFactory factory, PreInstaller installer) {
		this.factory = Objects.requireNonNull(factory, "factory");
		this.installer = Objects.requireNonNull(installer, "installer");
		this.enable = SystemProperties.boolValue(properyPrefix + ".enable", true);
	}

	PcapDispatcher newInstance(PcapDispatcher source) {
		return factory.newInstance(source, this);
	}

	@SuppressWarnings("unchecked")
	protected final T us() {
		return (T) this;
	}

	public final T enable(boolean enable) {
		boolean oldValue = this.enable;
		this.enable = enable;

		onEnableChange(oldValue, enable);

		return us();
	}

	protected void onEnableChange(boolean oldValue, boolean newValue) {

	}

	public final boolean isEnabled() {
		return enable;
	}

	public void activate() {
		installer.install((PreProcessor) this);
	}
}
