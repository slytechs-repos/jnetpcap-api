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
import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.util.PcapPacketRef;

import com.slytechs.jnetpcap.pro.PcapPro.PcapProContext;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public class AbstractPcapDispatcher implements PcapDispatcher {

	public interface PcapDispatcherFactory {
		PcapDispatcher newInstance(PcapDispatcher source, Object config, PcapProContext context);
	}

	private final PcapDispatcher pcapDispatcher;

	protected AbstractPcapDispatcher() {
		this.pcapDispatcher = null;
	}

	protected AbstractPcapDispatcher(PcapDispatcher pcapDispatcher) {
		this.pcapDispatcher = Objects.requireNonNull(pcapDispatcher, "pcapDispatcher");
	}

	@Override
	public PcapHeaderABI pcapHeaderABI() {
		return getPcapDispatcher().pcapHeaderABI();
	}

	/**
	 * @param address
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#captureLength(java.lang.foreign.MemorySegment)
	 */
	@Override
	public int captureLength(MemorySegment address) {
		return getPcapDispatcher().captureLength(address);
	}

	/**
	 * 
	 * @see org.jnetpcap.internal.PcapDispatcher#close()
	 */
	@Override
	public void close() {
		getPcapDispatcher().close();
	}

	/**
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#dispatchNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int dispatchNative(int count, NativeCallback handler, MemorySegment user) {
		return getPcapDispatcher().dispatchNative(count, handler, user);
	}

	/**
	 * @param count
	 * @param callbackFunc
	 * @param userData
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#dispatchRaw(int,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public int dispatchRaw(int count, MemorySegment callbackFunc, MemorySegment userData) {
		return getPcapDispatcher().dispatchRaw(count, callbackFunc, userData);
	}

	protected PcapDispatcher getPcapDispatcher() {
		return pcapDispatcher;
	}

	/**
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#getUncaughtException()
	 */
	@Override
	public RuntimeException getUncaughtException() {
		return getPcapDispatcher().getUncaughtException();
	}

	/**
	 * @param address
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#headerLength(java.lang.foreign.MemorySegment)
	 */
	@Override
	public int headerLength(MemorySegment address) {
		return getPcapDispatcher().headerLength(address);
	}

	/**
	 * 
	 * @see org.jnetpcap.internal.PcapDispatcher#interrupt()
	 */
	@Override
	public void interrupt() {
		getPcapDispatcher().interrupt();
	}

	/**
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#loopNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int loopNative(int count, NativeCallback handler, MemorySegment user) {
		return getPcapDispatcher().loopNative(count, handler, user);
	}

	/**
	 * @param count
	 * @param callbackFunc
	 * @param userData
	 * @return
	 * @see org.jnetpcap.internal.PcapDispatcher#loopRaw(int,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public int loopRaw(int count, MemorySegment callbackFunc, MemorySegment userData) {
		return getPcapDispatcher().loopRaw(count, callbackFunc, userData);
	}

	/**
	 * @param user
	 * @param header
	 * @param packet
	 * @see org.jnetpcap.PcapHandler.NativeCallback#nativeCallback(java.lang.foreign.MemorySegment,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public void nativeCallback(MemorySegment user, MemorySegment header, MemorySegment packet) {
		getPcapDispatcher().nativeCallback(user, header, packet);
	}

	@Override
	public PcapPacketRef next() throws PcapException {
		return pcapDispatcher.next();
	}

	@Override
	public PcapPacketRef nextEx() throws PcapException, TimeoutException {
		return pcapDispatcher.nextEx();
	}

	/**
	 * @param e
	 * @see org.jnetpcap.internal.PcapDispatcher#onNativeCallbackException(java.lang.RuntimeException)
	 */
	@Override
	public void onNativeCallbackException(RuntimeException e) {
		getPcapDispatcher().onNativeCallbackException(e);
	}

	/**
	 * @param exceptionHandler
	 * @see org.jnetpcap.internal.PcapDispatcher#setUncaughtExceptionHandler(java.lang.Thread.UncaughtExceptionHandler)
	 */
	@Override
	public void setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		getPcapDispatcher().setUncaughtExceptionHandler(exceptionHandler);
	}

}
