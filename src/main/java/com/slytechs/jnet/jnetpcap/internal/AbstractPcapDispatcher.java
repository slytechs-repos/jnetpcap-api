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
package com.slytechs.jnet.jnetpcap.internal;

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.foreign.MemorySegment;
import java.util.Objects;
import java.util.concurrent.TimeoutException;

import org.jnetpcap.PcapException;
import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.util.PcapPacketRef;

import com.slytechs.jnet.jnetpcap.PcapPro.PcapProContext;

/**
 * The Class AbstractPcapDispatcher.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class AbstractPcapDispatcher implements PcapDispatcher {

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
		PcapDispatcher newInstance(PcapDispatcher source, Object config, PcapProContext context);
	}

	/** The pcap dispatcher. */
	private final PcapDispatcher pcapDispatcher;

	/**
	 * Instantiates a new abstract pcap dispatcher.
	 */
	protected AbstractPcapDispatcher() {
		this.pcapDispatcher = null;
	}

	/**
	 * Instantiates a new abstract pcap dispatcher.
	 *
	 * @param pcapDispatcher the pcap dispatcher
	 */
	protected AbstractPcapDispatcher(PcapDispatcher pcapDispatcher) {
		this.pcapDispatcher = Objects.requireNonNull(pcapDispatcher, "pcapDispatcher");
	}

	/**
	 * @see org.jnetpcap.internal.PcapDispatcher#pcapHeaderABI()
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
	 * @see org.jnetpcap.internal.PcapDispatcher#captureLength(java.lang.foreign.MemorySegment)
	 */
	@Override
	public int captureLength(MemorySegment address) {
		return getPcapDispatcher().captureLength(address);
	}

	/**
	 * Close.
	 *
	 * @see org.jnetpcap.internal.PcapDispatcher#close()
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
	 * @see org.jnetpcap.internal.PcapDispatcher#dispatchNative(int,
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
	 * @see org.jnetpcap.internal.PcapDispatcher#dispatchRaw(int,
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
	protected PcapDispatcher getPcapDispatcher() {
		return pcapDispatcher;
	}

	/**
	 * Gets the uncaught exception.
	 *
	 * @return the uncaught exception
	 * @see org.jnetpcap.internal.PcapDispatcher#getUncaughtException()
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
	 * @see org.jnetpcap.internal.PcapDispatcher#headerLength(java.lang.foreign.MemorySegment)
	 */
	@Override
	public int headerLength(MemorySegment address) {
		return getPcapDispatcher().headerLength(address);
	}

	/**
	 * Interrupt.
	 *
	 * @see org.jnetpcap.internal.PcapDispatcher#interrupt()
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
	 * @see org.jnetpcap.internal.PcapDispatcher#loopNative(int,
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
	 * @see org.jnetpcap.internal.PcapDispatcher#loopRaw(int,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public int loopRaw(int count, MemorySegment callbackFunc, MemorySegment userData) {
		return getPcapDispatcher().loopRaw(count, callbackFunc, userData);
	}

	/**
	 * @see org.jnetpcap.internal.PcapDispatcher#next()
	 */
	@Override
	public PcapPacketRef next() throws PcapException {
		return pcapDispatcher.next();
	}

	/**
	 * @see org.jnetpcap.internal.PcapDispatcher#nextEx()
	 */
	@Override
	public PcapPacketRef nextEx() throws PcapException, TimeoutException {
		return pcapDispatcher.nextEx();
	}

	/**
	 * On native callback exception.
	 *
	 * @param e the e
	 * @see org.jnetpcap.internal.PcapDispatcher#onNativeCallbackException(java.lang.RuntimeException)
	 */
	@Override
	public void onNativeCallbackException(RuntimeException e) {
		getPcapDispatcher().onNativeCallbackException(e);
	}

	/**
	 * Sets the uncaught exception handler.
	 *
	 * @param exceptionHandler the new uncaught exception handler
	 * @see org.jnetpcap.internal.PcapDispatcher#setUncaughtExceptionHandler(java.lang.Thread.UncaughtExceptionHandler)
	 */
	@Override
	public void setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		getPcapDispatcher().setUncaughtExceptionHandler(exceptionHandler);
	}

	/**
	 * @see org.jnetpcap.PcapHandler.NativeCallback#nativeCallback(java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public void nativeCallback(MemorySegment user, MemorySegment header, MemorySegment packet) {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
