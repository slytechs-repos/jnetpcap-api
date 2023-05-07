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
import java.lang.foreign.MemoryAddress;
import java.util.Objects;

import org.jnetpcap.internal.PcapDispatcher;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public class AbstractPreProcessor implements PcapDispatcher {

	public interface PcapDispatcherFactory {
		PcapDispatcher newInstance(PcapDispatcher source, Object context);
	}

	private final PcapDispatcher pcapDispatcher;

	public AbstractPreProcessor(PcapDispatcher pcapDispatcher) {
		this.pcapDispatcher = Objects.requireNonNull(pcapDispatcher, "pcapDispatcher");
	}

	/**
	 * @param address
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#captureLength(java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int captureLength(MemoryAddress address) {
		return pcapDispatcher.captureLength(address);
	}

	/**
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#dispatchNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int dispatchNative(int count, NativeCallback handler, MemoryAddress user) {
		return pcapDispatcher.dispatchNative(count, handler, user);
	}

	/**
	 * @param count
	 * @param callbackFunc
	 * @param userData
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#dispatchRaw(int,
	 *      java.lang.foreign.MemoryAddress, java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int dispatchRaw(int count, MemoryAddress callbackFunc, MemoryAddress userData) {
		return pcapDispatcher.dispatchRaw(count, callbackFunc, userData);
	}

	/**
	 * @param address
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#headerLength(java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int headerLength(MemoryAddress address) {
		return pcapDispatcher.headerLength(address);
	}

	/**
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#loopNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int loopNative(int count, NativeCallback handler, MemoryAddress user) {
		return pcapDispatcher.loopNative(count, handler, user);
	}

	/**
	 * @param count
	 * @param callbackFunc
	 * @param userData
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#loopRaw(int,
	 *      java.lang.foreign.MemoryAddress, java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int loopRaw(int count, MemoryAddress callbackFunc, MemoryAddress userData) {
		return pcapDispatcher.loopRaw(count, callbackFunc, userData);
	}

	/**
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#getUncaughtException()
	 */
	@Override
	public RuntimeException getUncaughtException() {
		return pcapDispatcher.getUncaughtException();
	}

	/**
	 * @param exceptionHandler
	 * @see org.jnetpcap.internal.PcapDispatcher#setUncaughtExceptionHandler(java.lang.Thread.UncaughtExceptionHandler)
	 */
	@Override
	public void setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		pcapDispatcher.setUncaughtExceptionHandler(exceptionHandler);
	}

	/**
	 * 
	 * @see org.jnetpcap.internal.PcapDispatcher#close()
	 */
	@Override
	public void close() {
		pcapDispatcher.close();
	}

	/**
	 * @param user
	 * @param header
	 * @param packet
	 * @see org.jnetpcap.PcapHandler.NativeCallback#nativeCallback(java.lang.foreign.MemoryAddress,
	 *      java.lang.foreign.MemoryAddress, java.lang.foreign.MemoryAddress)
	 */
	@Override
	public void nativeCallback(MemoryAddress user, MemoryAddress header, MemoryAddress packet) {
		pcapDispatcher.nativeCallback(user, header, packet);
	}

	/**
	 * @param e
	 * @see org.jnetpcap.internal.PcapDispatcher#onNativeCallbackException(java.lang.RuntimeException)
	 */
	@Override
	public void onNativeCallbackException(RuntimeException e) {
		pcapDispatcher.onNativeCallbackException(e);
	}

	/**
	 * 
	 * @see org.jnetpcap.internal.PcapDispatcher#interrupt()
	 */
	@Override
	public void interrupt() {
		pcapDispatcher.interrupt();
	}

}
