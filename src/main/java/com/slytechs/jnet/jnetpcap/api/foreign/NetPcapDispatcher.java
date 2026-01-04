/*
 * Copyright 2005-2025 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.jnet.jnetpcap.api.foreign;

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.concurrent.TimeoutException;

import com.slytechs.sdk.common.foreign.ForeignUpcall;
import com.slytechs.sdk.common.foreign.ForeignUtils;
import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.jnetpcap.internal.PcapHeaderABI;
import com.slytechs.sdk.protocol.core.descriptor.PcapDescriptorPadded;

import static java.lang.foreign.ValueLayout.*;

/**
 * A proxy PcapHandler, which receives packets from native pcap handle and
 * forwards all packets to the sink java PcapHandler.
 */
public class NetPcapDispatcher {

	/**
	 * The Constant pcap_geterr.
	 *
	 * @see {@code char *pcap_geterr(pcap_t *p)}
	 * @since libpcap 0.4
	 */
	private static final NetPcapForeignDowncall pcap_geterr;

	/**
	 * The Constant pcap_dispatch.
	 *
	 * @see {@code int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback,
	 *      u_char *user)}
	 * @since libpcap 0.4
	 */
	static final NetPcapForeignDowncall pcap_dispatch;

	/**
	 * The Constant pcap_loop.
	 *
	 * @see {@code int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char
	 *      *user)}
	 * @since libpcap 0.4
	 */
	private static final NetPcapForeignDowncall pcap_loop;

	/**
	 * This upcall foreign reference is a callback method that is called to java
	 * from pcap_loop and pcap_dispatch calls.
	 * 
	 * @see {@code typedef void (*pcap_handler)(u_char *user, const struct
	 *      pcap_pkthdr *h, const u_char *bytes);}
	 * @since libpcap 0.4
	 */
	static final ForeignUpcall<NativeUpcall> foreignUpcall;

	/**
	 * The Constant pcap_next.
	 *
	 * @see {@code const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)}
	 * @since libpcap 0.4
	 */
	private static final NetPcapForeignDowncall pcap_next;

	/**
	 * The Constant pcap_next_ex.
	 *
	 * @see {@code int pcap_next_ex (pcap_t *p, struct pcap_pkthdr **pkt_header,
	 *      const u_char **pkt_data)}
	 * @since libpcap 0.8
	 */
	private static final NetPcapForeignDowncall pcap_next_ex;

	static {

		try (var foreign = new NetPcapForeignInitializer(NetPcapDispatcher.class)) {

			// @formatter:off
			foreignUpcall    = foreign.upcall  ("nativeUpcall(AAA)V", NativeUpcall.class);
			pcap_geterr      = foreign.downcall("pcap_geterr(A)A");
			pcap_dispatch    = foreign.downcall("pcap_dispatch(AIAA)I");
			pcap_loop        = foreign.downcall("pcap_loop(AIAA)I");
			pcap_next        = foreign.downcall("pcap_next(AA)A");
			pcap_next_ex     = foreign.downcall("pcap_next_ex(AAA)I");
		// @formatter:on

		}
	}

	/** The pcap callback stub. */
	private final MemorySegment pcapCallbackStub;

	/** The pcap handle. */
	private final MemorySegment pcapHandle;

	/** The arena. */
	protected final Arena arena;

	/** The uncaught exception handler. */
	private UncaughtExceptionHandler uncaughtExceptionHandler;

	/** The uncaught exception. */
	private RuntimeException uncaughtException;

	/** The interrupted. */
	private boolean interrupted = false;

	/** The interrupt on errors. */
	@SuppressWarnings("unused")
	private boolean interruptOnErrors = true;

	/** The break dispatch. */
	private final Runnable breakDispatch;

	/** The abi. */
	private final PcapHeaderABI abi;

	private final UserUpcall userUpcall;

	/**
	 * Instantiates a new standard pcap dispatcher.
	 *
	 * @param pcapHandle    the pcap handle
	 * @param abi           the abi
	 * @param breakDispatch the break dispatch
	 */
	public NetPcapDispatcher(MemorySegment pcapHandle, PcapHeaderABI abi, Runnable breakDispatch) {
		this.pcapHandle = pcapHandle;
		this.abi = abi;
		this.breakDispatch = breakDispatch;
		this.arena = Arena.ofShared();
		this.userUpcall = new UserUpcall(abi);
		this.pcapCallbackStub = foreignUpcall.virtualStubPointer(userUpcall, this.arena);
	}

	public UserUpcall userUpcall() {
		return userUpcall;
	}

	/**
	 * Gets the last pcap error string.
	 *
	 * @return the err
	 */
	public final String geterr() {
		return pcap_geterr.invokeString(pcapHandle);
	}

	public final int dispatchRaw(int count, MemorySegment userData) {

		if (Thread.currentThread().isInterrupted()) {
			handleInterrupt();

			return -1;
		}

		int result = pcap_dispatch.invokeInt(
				pcapHandle,
				count,
				pcapCallbackStub,
				userData);

		if (interrupted)
			handleInterrupt();

		return result;
	}

	public final RuntimeException getUncaughtException() {
		return uncaughtException;
	}

	/**
	 * Handle interrupt.
	 *
	 * @throws RuntimeException the runtime exception
	 */
	private final void handleInterrupt() throws RuntimeException {
		interrupted = false; // Reset flag

		if (uncaughtException != null) {
			throw uncaughtException;
		}
	}

	public final void interrupt() {
		this.breakDispatch.run();
		this.interrupted = true;
	}

	public final int loopRaw(int count, MemorySegment userData) {
		int result = pcap_loop.invokeInt(
				pcapHandle,
				count,
				pcapCallbackStub,
				userData);

		if (interrupted)
			handleInterrupt();

		return result;
	}

	public final void onNativeCallbackException(RuntimeException e) {
		this.uncaughtException = e;

		if (uncaughtExceptionHandler != null) {
			var veto = VetoableExceptionHandler.wrap(uncaughtExceptionHandler);
			if (veto.vetoableException(e)) {
				this.uncaughtException = e;
				interrupt();
			}

		} else {
			this.uncaughtException = e;
			interrupt();
		}
	}

	public final void setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		this.uncaughtExceptionHandler = exceptionHandler;
	}

	/** The pointer to pointer1. */
	private final MemorySegment POINTER_TO_POINTER1 = Arena.ofAuto().allocate(ADDRESS);

	/** The pointer to pointer2. */
	private final MemorySegment POINTER_TO_POINTER2 = Arena.ofAuto().allocate(ADDRESS);

	/** The pcap header buffer. */
	private final MemorySegment PCAP_HEADER_BUFFER = Arena.ofAuto().allocate(PcapDescriptorPadded.BYTE_SIZE);

	/**
	 * Dynamic non-pcap utility method to convert libpcap error code to a string, by
	 * various fallback methods with an active pcap handle.
	 *
	 * @param error the code
	 * @return the error string
	 */
	protected String getErrorString(int error) {
		String msg = this.geterr();

		return msg;
	}

	public void nextEx(MemorySegmentPair pair) throws PcapException, TimeoutException {
		int result = pcap_next_ex.invokeInt(
				pcapHandle,
				POINTER_TO_POINTER1,
				POINTER_TO_POINTER2);

		switch (result) {
		case 1: // Success - packet available
			break;

		case 0: // Timeout (live capture only)
			throw new TimeoutException();

		case -2: // EOF (offline) or breakloop called
			pair.hdr = null;
			pair.pkt = null;
			return;

		case -1: // Error
		default:
			throw new PcapException(geterr());
		}

		// Only reach here on success (result == 1)
		MemorySegment hdr = POINTER_TO_POINTER1.get(ADDRESS, 0);
		MemorySegment pkt = POINTER_TO_POINTER2.get(ADDRESS, 0);

		// Reinterpret header FIRST, then read caplen
		hdr = hdr.reinterpret(abi.headerLength());
		int caplen = abi.captureLength(hdr);
		pkt = pkt.reinterpret(caplen);

		pair.hdr = hdr;
		pair.pkt = pkt;
	}

	public void next(MemorySegmentPair pair) throws PcapException {
		MemorySegment hdr = PCAP_HEADER_BUFFER;
		MemorySegment pkt = pcap_next.invokeObj(pcapHandle, hdr);

		// Null return means timeout or EOF (pcap_next doesn't distinguish)
		if (ForeignUtils.isNullAddress(pkt)) {
			pair.pkt = null;
			pair.hdr = null;
			return;
		}

		// Header buffer is pre-allocated with correct size, no reinterpret needed
		int caplen = abi.captureLength(hdr);
		pkt = pkt.reinterpret(caplen);

		pair.hdr = hdr;
		pair.pkt = pkt;
	}
}