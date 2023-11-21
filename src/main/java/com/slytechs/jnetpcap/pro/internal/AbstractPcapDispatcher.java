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
package com.slytechs.jnetpcap.pro.internal;

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.foreign.MemorySegment;
import java.util.Objects;
import java.util.concurrent.TimeoutException;

import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.internal.PacketDispatcher;
import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.util.PcapPacketRef;

import com.slytechs.jnetpcap.pro.PcapPro.PcapProContext;

/**
 * The Class AbstractPcapDispatcher.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class AbstractPcapDispatcher implements PacketDispatcher {

	/**
	 * A factory for creating PcapDispatcher objects.
	 */
	public interface PcapDispatcherFactory {
		
		/**
		 * New instance.
		 *
		 * @param source  the source
		 * @param config  the config
		 * @param context the context
		 * @return the pcap dispatcher
		 */
		PacketDispatcher newInstance(PacketDispatcher source, Object config, PcapProContext context);
	}

	/** The pcap dispatcher. */
	private final PacketDispatcher packetDispatcher;

	/**
	 * Instantiates a new abstract pcap dispatcher.
	 */
	protected AbstractPcapDispatcher() {
		this.packetDispatcher = null;
	}

	/**
	 * Instantiates a new abstract pcap dispatcher.
	 *
	 * @param packetDispatcher the pcap dispatcher
	 */
	protected AbstractPcapDispatcher(PacketDispatcher packetDispatcher) {
		this.packetDispatcher = Objects.requireNonNull(packetDispatcher, "pcapDispatcher");
	}

	/**
	 * @see org.jnetpcap.internal.PacketDispatcher#pcapHeaderABI()
	 */
	@Override
	public PcapHeaderABI pcapHeaderABI() {
		return getPcapDispatcher().pcapHeaderABI();
	}

	/**
	 * Capture length.
	 *
	 * @param address the address
	 * @return the int
	 * @see org.jnetpcap.internal.PacketDispatcher#captureLength(java.lang.foreign.MemorySegment)
	 */
	@Override
	public int captureLength(MemorySegment address) {
		return getPcapDispatcher().captureLength(address);
	}

	/**
	 * Close.
	 *
	 * @see org.jnetpcap.internal.PacketDispatcher#close()
	 */
	@Override
	public void close() {
		getPcapDispatcher().close();
	}

	/**
	 * Dispatch native.
	 *
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 * @see org.jnetpcap.internal.PacketDispatcher#dispatchNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int dispatchNative(int count, NativeCallback handler, MemorySegment user) {
		return getPcapDispatcher().dispatchNative(count, handler, user);
	}

	/**
	 * Dispatch raw.
	 *
	 * @param count        the count
	 * @param callbackFunc the callback func
	 * @param userData     the user data
	 * @return the int
	 * @see org.jnetpcap.internal.PacketDispatcher#dispatchRaw(int,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public int dispatchRaw(int count, MemorySegment callbackFunc, MemorySegment userData) {
		return getPcapDispatcher().dispatchRaw(count, callbackFunc, userData);
	}

	/**
	 * Gets the pcap dispatcher.
	 *
	 * @return the pcap dispatcher
	 */
	protected PacketDispatcher getPcapDispatcher() {
		return packetDispatcher;
	}

	/**
	 * Gets the uncaught exception.
	 *
	 * @return the uncaught exception
	 * @see org.jnetpcap.internal.PacketDispatcher#getUncaughtException()
	 */
	@Override
	public RuntimeException getUncaughtException() {
		return getPcapDispatcher().getUncaughtException();
	}

	/**
	 * Header length.
	 *
	 * @param address the address
	 * @return the int
	 * @see org.jnetpcap.internal.PacketDispatcher#headerLength(java.lang.foreign.MemorySegment)
	 */
	@Override
	public int headerLength(MemorySegment address) {
		return getPcapDispatcher().headerLength(address);
	}

	/**
	 * Interrupt.
	 *
	 * @see org.jnetpcap.internal.PacketDispatcher#interrupt()
	 */
	@Override
	public void interrupt() {
		getPcapDispatcher().interrupt();
	}

	/**
	 * Loop native.
	 *
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 * @see org.jnetpcap.internal.PacketDispatcher#loopNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int loopNative(int count, NativeCallback handler, MemorySegment user) {
		return getPcapDispatcher().loopNative(count, handler, user);
	}

	/**
	 * Loop raw.
	 *
	 * @param count        the count
	 * @param callbackFunc the callback func
	 * @param userData     the user data
	 * @return the int
	 * @see org.jnetpcap.internal.PacketDispatcher#loopRaw(int,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public int loopRaw(int count, MemorySegment callbackFunc, MemorySegment userData) {
		return getPcapDispatcher().loopRaw(count, callbackFunc, userData);
	}

	/**
	 * @see org.jnetpcap.internal.PacketDispatcher#next()
	 */
	@Override
	public PcapPacketRef next() throws PcapException {
		return packetDispatcher.next();
	}

	/**
	 * @see org.jnetpcap.internal.PacketDispatcher#nextEx()
	 */
	@Override
	public PcapPacketRef nextEx() throws PcapException, TimeoutException {
		return packetDispatcher.nextEx();
	}

	/**
	 * On native callback exception.
	 *
	 * @param e the e
	 * @see org.jnetpcap.internal.PacketDispatcher#onNativeCallbackException(java.lang.RuntimeException)
	 */
	@Override
	public void onNativeCallbackException(RuntimeException e) {
		getPcapDispatcher().onNativeCallbackException(e);
	}

	/**
	 * Sets the uncaught exception handler.
	 *
	 * @param exceptionHandler the new uncaught exception handler
	 * @see org.jnetpcap.internal.PacketDispatcher#setUncaughtExceptionHandler(java.lang.Thread.UncaughtExceptionHandler)
	 */
	@Override
	public void setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		getPcapDispatcher().setUncaughtExceptionHandler(exceptionHandler);
	}

}
