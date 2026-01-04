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
package com.slytechs.jnet.jnetpcap.api;

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import com.slytechs.sdk.jnetpcap.BpFilter;
import com.slytechs.sdk.jnetpcap.Pcap;
import com.slytechs.sdk.jnetpcap.PcapActivatedException;
import com.slytechs.sdk.jnetpcap.PcapDumper;
import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.jnetpcap.PcapHandler.NativeCallback;
import com.slytechs.sdk.jnetpcap.PcapHandler.OfArray;
import com.slytechs.sdk.jnetpcap.PcapHandler.OfMemorySegment;
import com.slytechs.sdk.jnetpcap.PcapStat;
import com.slytechs.sdk.jnetpcap.constant.PcapDirection;
import com.slytechs.sdk.jnetpcap.constant.PcapDlt;
import com.slytechs.sdk.jnetpcap.constant.PcapTStampPrecision;
import com.slytechs.sdk.jnetpcap.constant.PcapTstampType;
import com.slytechs.sdk.jnetpcap.internal.PcapHeaderABI;
import com.slytechs.sdk.protocol.core.Packet;

/**
 * Base class for NetPcap providing delegation to low-level Pcap bindings.
 * 
 * <p>
 * This class wraps a {@link Pcap} instance and provides pass-through access to
 * all pcap operations. Fluent setter methods return {@code BaseNetPcap} to
 * enable method chaining with covariant return type overrides in subclasses.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public abstract class BaseNetPcap implements AutoCloseable {

	protected final Pcap pcapApi;

	protected BaseNetPcap(Pcap pcapApi) {
		this.pcapApi = pcapApi;
	}

	/**
	 * Activates a pcap handle created with {@code create()}.
	 *
	 * @throws PcapActivatedException if handle is already activated
	 * @throws PcapException          if activation fails
	 * @see Pcap#activate()
	 */
	public void activate() throws PcapActivatedException, PcapException {
		pcapApi.activate();
	}

	/**
	 * Forces a {@code dispatch()} or {@code loop()} call to return.
	 * 
	 * @see Pcap#breakloop()
	 */
	public void breakloop() {
		pcapApi.breakloop();
	}

	/**
	 * Checks whether monitor mode can be set on this capture handle.
	 *
	 * @return true if monitor mode can be set
	 * @throws PcapException if operation fails
	 * @see Pcap#canSetRfmon()
	 */
	public boolean canSetRfmon() throws PcapException {
		return pcapApi.canSetRfmon();
	}

	/**
	 * Closes the capture handle and releases resources.
	 * 
	 * @see Pcap#close()
	 */
	@Override
	public void close() {
		pcapApi.close();
	}

	/**
	 * Compiles a filter expression into a BPF program.
	 *
	 * @param str      the filter expression
	 * @param optimize true to optimize the compiled code
	 * @return the compiled BPF program
	 * @throws PcapException if compilation fails
	 * @see Pcap#compile(String, boolean)
	 */
	public BpFilter compile(String str, boolean optimize) throws PcapException {
		return pcapApi.compile(str, optimize);
	}

	/**
	 * Compiles a filter expression with netmask.
	 *
	 * @param str      the filter expression
	 * @param optimize true to optimize the compiled code
	 * @param netmask  the network mask
	 * @return the compiled BPF program
	 * @throws PcapException if compilation fails
	 * @see Pcap#compile(String, boolean, int)
	 */
	public BpFilter compile(String str, boolean optimize, int netmask) throws PcapException {
		return pcapApi.compile(str, optimize, netmask);
	}

	/**
	 * Returns the link-layer header type.
	 *
	 * @return the data link type
	 * @throws PcapException if operation fails
	 * @see Pcap#datalink()
	 */
	public PcapDlt datalink() throws PcapException {
		return pcapApi.datalink();
	}

	/**
	 * Returns the link-layer header type with extended information.
	 *
	 * @return the data link type
	 * @throws PcapException if operation fails
	 * @see Pcap#dataLinkExt()
	 */
	public PcapDlt dataLinkExt() throws PcapException {
		return pcapApi.dataLinkExt();
	}

	/**
	 * Processes packets using a native callback.
	 *
	 * @param count   maximum packets to process
	 * @param handler the native callback handler
	 * @param user    user data passed to callback
	 * @return number of packets processed
	 * @see Pcap#dispatch(int, NativeCallback, MemorySegment)
	 */
	public int dispatch(int count, NativeCallback handler, MemorySegment user) {
		return pcapApi.dispatch(count, handler, user);
	}

	/**
	 * Processes packets using an array-based handler.
	 *
	 * @param <U>     the user data type
	 * @param count   maximum packets to process
	 * @param handler the array handler
	 * @param user    user data passed to handler
	 * @return number of packets processed
	 * @throws PcapException if operation fails
	 * @see Pcap#dispatch(int, OfArray, Object)
	 */
	public <U> int dispatch(int count, OfArray<U> handler, U user) throws PcapException {
		return pcapApi.dispatch(count, handler, user);
	}

	/**
	 * Processes packets using a memory segment handler.
	 *
	 * @param <U>     the user data type
	 * @param count   maximum packets to process
	 * @param handler the memory segment handler
	 * @param user    user data passed to handler
	 * @return number of packets processed
	 * @throws PcapException if operation fails
	 * @see Pcap#dispatch(int, OfMemorySegment, Object)
	 */
	public <U> int dispatch(int count, OfMemorySegment<U> handler, U user) throws PcapException {
		return pcapApi.dispatch(count, handler, user);
	}

	/**
	 * Processes packets and writes them to a dump file.
	 *
	 * @param <U>        the user data type
	 * @param count      maximum packets to process
	 * @param pcapDumper the dump file handle
	 * @return number of packets processed
	 * @throws PcapException if operation fails
	 * @see Pcap#dispatch(int, PcapDumper)
	 */
	public <U> int dispatch(int count, PcapDumper pcapDumper) throws PcapException {
		return pcapApi.dispatch(count, pcapDumper);
	}

	/**
	 * Opens a dump file for writing packets.
	 *
	 * @param fname the output filename
	 * @return a PcapDumper for writing packets
	 * @throws PcapException if file cannot be opened
	 * @see Pcap#dumpOpen(String)
	 */
	public PcapDumper dumpOpen(String fname) throws PcapException {
		return pcapApi.dumpOpen(fname);
	}

	/**
	 * Returns the error message for the last pcap error.
	 *
	 * @return the error message string
	 * @see Pcap#geterr()
	 */
	public String geterr() {
		return pcapApi.geterr();
	}

	/**
	 * Returns the device name associated with this handle.
	 *
	 * @return the device name
	 * @see Pcap#getName()
	 */
	public final String getName() {
		return pcapApi.getName();
	}

	/**
	 * Returns the current non-blocking mode state.
	 *
	 * @return true if in non-blocking mode
	 * @throws PcapException if operation fails
	 * @see Pcap#getNonBlock()
	 */
	public boolean getNonBlock() throws PcapException {
		return pcapApi.getNonBlock();
	}

	/**
	 * Returns the pcap header ABI information.
	 *
	 * @return the header ABI
	 * @see Pcap#getPcapHeaderABI()
	 */
	public PcapHeaderABI getPcapHeaderABI() {
		return pcapApi.getPcapHeaderABI();
	}

	/**
	 * Returns the timestamp precision for this handle.
	 *
	 * @return the timestamp precision
	 * @throws PcapException if operation fails
	 * @see Pcap#getTstampPrecision()
	 */
	public PcapTStampPrecision getTstampPrecision() throws PcapException {
		return pcapApi.getTstampPrecision();
	}

	/**
	 * Transmits a packet, returning the number of bytes sent.
	 *
	 * @param array the packet data
	 * @return number of bytes sent
	 * @throws PcapException if transmission fails
	 * @see Pcap#inject(byte[])
	 */
	public final int inject(byte[] array) throws PcapException {
		return pcapApi.inject(array);
	}

	/**
	 * Transmits a portion of a packet array.
	 *
	 * @param array  the packet data
	 * @param offset starting offset
	 * @param length number of bytes to send
	 * @return number of bytes sent
	 * @throws PcapException if transmission fails
	 * @see Pcap#inject(byte[], int, int)
	 */
	public final int inject(byte[] array, int offset, int length) throws PcapException {
		return pcapApi.inject(array, offset, length);
	}

	/**
	 * Transmits a packet from a ByteBuffer.
	 *
	 * @param buf the packet data
	 * @return number of bytes sent
	 * @throws PcapException if transmission fails
	 * @see Pcap#inject(ByteBuffer)
	 */
	public final int inject(ByteBuffer buf) throws PcapException {
		return pcapApi.inject(buf);
	}

	/**
	 * Transmits a packet from native memory.
	 *
	 * @param packet the packet data
	 * @param length number of bytes to send
	 * @return number of bytes sent
	 * @throws PcapException if transmission fails
	 * @see Pcap#inject(MemorySegment, int)
	 */
	public int inject(MemorySegment packet, int length) throws PcapException {
		return pcapApi.inject(packet, length);
	}

	/**
	 * Checks if the capture file has different byte order.
	 *
	 * @return true if byte-swapped
	 * @throws PcapException if operation fails
	 * @see Pcap#isSwapped()
	 */
	public boolean isSwapped() throws PcapException {
		return pcapApi.isSwapped();
	}

	/**
	 * Returns the list of supported data link types.
	 *
	 * @return list of supported link types
	 * @throws PcapException if operation fails
	 * @see Pcap#listDataLinks()
	 */
	public List<PcapDlt> listDataLinks() throws PcapException {
		return pcapApi.listDataLinks();
	}

	/**
	 * Returns the list of supported timestamp types.
	 *
	 * @return list of supported timestamp types
	 * @throws PcapException if operation fails
	 * @see Pcap#listTstampTypes()
	 */
	public List<PcapTstampType> listTstampTypes() throws PcapException {
		return pcapApi.listTstampTypes();
	}

	/**
	 * Processes packets in a loop using a native callback.
	 *
	 * @param <U>     the user data type
	 * @param count   packets to process (-1 for infinite)
	 * @param handler the native callback
	 * @param user    user data
	 * @return number of packets processed
	 * @see Pcap#loop(int, NativeCallback, MemorySegment)
	 */
	public <U> int loop(int count, NativeCallback handler, MemorySegment user) {
		return pcapApi.loop(count, handler, user);
	}

	/**
	 * Processes packets in a loop using an array handler.
	 *
	 * @param <U>     the user data type
	 * @param count   packets to process (-1 for infinite)
	 * @param handler the array handler
	 * @param user    user data
	 * @return number of packets processed
	 * @throws PcapException if operation fails
	 * @see Pcap#loop(int, OfArray, Object)
	 */
	public <U> int loop(int count, OfArray<U> handler, U user) throws PcapException {
		return pcapApi.loop(count, handler, user);
	}

	/**
	 * Processes packets in a loop using a memory segment handler.
	 *
	 * @param <U>     the user data type
	 * @param count   packets to process (-1 for infinite)
	 * @param handler the memory segment handler
	 * @param user    user data
	 * @return number of packets processed
	 * @see Pcap#loop(int, OfMemorySegment, Object)
	 */
	public <U> int loop(int count, OfMemorySegment<U> handler, U user) {
		return pcapApi.loop(count, handler, user);
	}

	/**
	 * Processes packets in a loop and writes to a dump file.
	 *
	 * @param <U>        the user data type
	 * @param count      packets to process (-1 for infinite)
	 * @param pcapDumper the dump file handle
	 * @return number of packets processed
	 * @throws PcapException if operation fails
	 * @see Pcap#loop(int, PcapDumper)
	 */
	public <U> int loop(int count, PcapDumper pcapDumper) throws PcapException {
		return pcapApi.loop(count, pcapDumper);
	}

	/**
	 * Returns the major version of the pcap file format.
	 *
	 * @return the major version number
	 * @throws PcapException if operation fails
	 * @see Pcap#majorVersion()
	 */
	public int majorVersion() throws PcapException {
		return pcapApi.majorVersion();
	}

	/**
	 * Returns the minor version of the pcap file format.
	 *
	 * @return the minor version number
	 * @throws PcapException if operation fails
	 * @see Pcap#minorVersion()
	 */
	public int minorVersion() throws PcapException {
		return pcapApi.minorVersion();
	}

	/**
	 * Retrieves the next packet.
	 *
	 * @return the next packet, or null if none available
	 * @throws PcapException if operation fails
	 * @see Pcap#next()
	 */
	public abstract Packet next() throws PcapException;

	/**
	 * Retrieves the next packet with extended status.
	 *
	 * @return the next packet
	 * @throws PcapException    if operation fails or EOF reached
	 * @throws TimeoutException if read timeout expires
	 * @see Pcap#nextEx()
	 */
	public abstract Packet nextEx() throws PcapException, TimeoutException;

	/**
	 * Returns the byte order of the capture file.
	 *
	 * @return the byte order
	 * @throws PcapException if operation fails
	 * @see Pcap#order()
	 */
	public final ByteOrder order() throws PcapException {
		return pcapApi.order();
	}

	/**
	 * Prints error message to stderr.
	 *
	 * @param prefix prefix for the error message
	 * @return this instance for method chaining
	 * @see Pcap#perror(String)
	 */
	public BaseNetPcap perror(String prefix) {
		pcapApi.perror(prefix);
		return this;
	}

	/**
	 * Sends a raw packet on the network.
	 *
	 * @param buf the packet data
	 * @throws PcapException if transmission fails
	 * @see Pcap#sendPacket(byte[])
	 */
	public final void sendPacket(byte[] buf) throws PcapException {
		pcapApi.sendPacket(buf);
	}

	/**
	 * Sends a portion of a raw packet.
	 *
	 * @param buf    the packet data
	 * @param offset starting offset
	 * @param length number of bytes to send
	 * @throws PcapException if transmission fails
	 * @see Pcap#sendPacket(byte[], int, int)
	 */
	public final void sendPacket(byte[] buf, int offset, int length) throws PcapException {
		pcapApi.sendPacket(buf, offset, length);
	}

	/**
	 * Sends a raw packet from a ByteBuffer.
	 *
	 * @param buf the packet data
	 * @throws PcapException if transmission fails
	 * @see Pcap#sendPacket(ByteBuffer)
	 */
	public final void sendPacket(ByteBuffer buf) throws PcapException {
		pcapApi.sendPacket(buf);
	}

	/**
	 * Sends a raw packet from native memory.
	 *
	 * @param packet the packet data
	 * @param length number of bytes to send
	 * @throws PcapException if transmission fails
	 * @see Pcap#sendPacket(MemorySegment, int)
	 */
	public void sendPacket(MemorySegment packet, int length) throws PcapException {
		pcapApi.sendPacket(packet, length);
	}

	/**
	 * Sets the kernel buffer size for the capture.
	 *
	 * @param bufferSize the buffer size in bytes
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setBufferSize(int)
	 */
	public BaseNetPcap setBufferSize(int bufferSize) throws PcapException {
		pcapApi.setBufferSize(bufferSize);
		return this;
	}

	/**
	 * Sets the data link type for the capture.
	 *
	 * @param dlt the data link type value
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setDatalink(int)
	 */
	public BaseNetPcap setDatalink(int dlt) throws PcapException {
		pcapApi.setDatalink(dlt);
		return this;
	}

	/**
	 * Sets the data link type using an Optional.
	 *
	 * @param dlt the optional data link type
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setDatalink(Optional)
	 */
	public BaseNetPcap setDatalink(Optional<PcapDlt> dlt) throws PcapException {
		pcapApi.setDatalink(dlt);
		return this;
	}

	/**
	 * Sets the data link type.
	 *
	 * @param dlt the data link type
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setDatalink(PcapDlt)
	 */
	public BaseNetPcap setDatalink(PcapDlt dlt) throws PcapException {
		pcapApi.setDatalink(dlt);
		return this;
	}

	/**
	 * Sets the capture direction.
	 *
	 * @param dir the direction value
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setDirection(int)
	 */
	public BaseNetPcap setDirection(int dir) throws PcapException {
		pcapApi.setDirection(dir);
		return this;
	}

	/**
	 * Sets the capture direction using an Optional.
	 *
	 * @param dir the optional direction
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setDirection(Optional)
	 */
	public BaseNetPcap setDirection(Optional<PcapDirection> dir) throws PcapException {
		pcapApi.setDirection(dir);
		return this;
	}

	/**
	 * Sets the capture direction.
	 *
	 * @param dir the direction
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setDirection(PcapDirection)
	 */
	public BaseNetPcap setDirection(PcapDirection dir) throws PcapException {
		pcapApi.setDirection(dir);
		return this;
	}

	/**
	 * Sets the BPF filter program.
	 *
	 * @param bpfProgram the compiled filter program
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setFilter(BpFilter)
	 */
	public BaseNetPcap setFilter(BpFilter bpfProgram) throws PcapException {
		pcapApi.setFilter(bpfProgram);
		return this;
	}

	/**
	 * Sets the BPF filter using an Optional.
	 *
	 * @param bpfProgram the optional filter program
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setFilter(Optional)
	 */
	public BaseNetPcap setFilter(Optional<BpFilter> bpfProgram) throws PcapException {
		pcapApi.setFilter(bpfProgram);
		return this;
	}

	/**
	 * Enables or disables immediate mode.
	 *
	 * @param enable true to enable immediate mode
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setImmediateMode(boolean)
	 */
	public BaseNetPcap setImmediateMode(boolean enable) throws PcapException {
		pcapApi.setImmediateMode(enable);
		return this;
	}

	/**
	 * Enables or disables non-blocking mode.
	 *
	 * @param nonBlock true for non-blocking mode
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setNonBlock(boolean)
	 */
	public BaseNetPcap setNonBlock(boolean nonBlock) throws PcapException {
		pcapApi.setNonBlock(nonBlock);
		return this;
	}

	/**
	 * Enables or disables promiscuous mode.
	 *
	 * @param promiscuousMode true for promiscuous mode
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setPromisc(boolean)
	 */
	public BaseNetPcap setPromisc(boolean promiscuousMode) throws PcapException {
		pcapApi.setPromisc(promiscuousMode);
		return this;
	}

	/**
	 * Enables or disables monitor mode (wireless).
	 *
	 * @param rfMonitor true to enable monitor mode
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setRfmon(boolean)
	 */
	public BaseNetPcap setRfmon(boolean rfMonitor) throws PcapException {
		pcapApi.setRfmon(rfMonitor);
		return this;
	}

	/**
	 * Sets the snapshot length.
	 *
	 * @param snaplen maximum bytes to capture per packet
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setSnaplen(int)
	 */
	public BaseNetPcap setSnaplen(int snaplen) throws PcapException {
		pcapApi.setSnaplen(snaplen);
		return this;
	}

	/**
	 * Sets the read timeout in milliseconds.
	 *
	 * @param timeoutInMillis timeout in milliseconds
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setTimeout(int)
	 */
	public BaseNetPcap setTimeout(int timeoutInMillis) throws PcapException {
		pcapApi.setTimeout(timeoutInMillis);
		return this;
	}

	/**
	 * Sets the timestamp precision.
	 *
	 * @param precision the timestamp precision
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setTstampPrecision(PcapTStampPrecision)
	 */
	public BaseNetPcap setTstampPrecision(PcapTStampPrecision precision) throws PcapException {
		pcapApi.setTstampPrecision(precision);
		return this;
	}

	/**
	 * Sets the timestamp type.
	 *
	 * @param type the timestamp type
	 * @return this instance for method chaining
	 * @throws PcapException if operation fails
	 * @see Pcap#setTstampType(PcapTstampType)
	 */
	public BaseNetPcap setTstampType(PcapTstampType type) throws PcapException {
		pcapApi.setTstampType(type);
		return this;
	}

	/**
	 * Sets the uncaught exception handler using a Consumer.
	 *
	 * @param exceptionHandler the exception handler
	 * @return this instance for method chaining
	 * @see Pcap#setUncaughtExceptionHandler(Consumer)
	 */
	public BaseNetPcap setUncaughtExceptionHandler(Consumer<? super Throwable> exceptionHandler) {
		pcapApi.setUncaughtExceptionHandler(exceptionHandler);
		return this;
	}

	/**
	 * Sets the uncaught exception handler.
	 *
	 * @param exceptionHandler the exception handler
	 * @return this instance for method chaining
	 * @see Pcap#setUncaughtExceptionHandler(UncaughtExceptionHandler)
	 */
	public BaseNetPcap setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		pcapApi.setUncaughtExceptionHandler(exceptionHandler);
		return this;
	}

	/**
	 * Returns the snapshot length.
	 *
	 * @return the snapshot length
	 * @throws PcapException if operation fails
	 * @see Pcap#snapshot()
	 */
	public int snapshot() throws PcapException {
		return pcapApi.snapshot();
	}

	/**
	 * Returns capture statistics.
	 *
	 * @return the capture statistics
	 * @throws PcapException if operation fails
	 * @see Pcap#stats()
	 */
	public PcapStat stats() throws PcapException {
		return pcapApi.stats();
	}
}