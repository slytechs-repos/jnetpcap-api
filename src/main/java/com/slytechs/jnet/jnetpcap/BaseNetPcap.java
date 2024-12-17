/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.jnetpcap.BpFilter;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapActivatedException;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.PcapHandler.OfArray;
import org.jnetpcap.PcapHandler.OfMemorySegment;
import org.jnetpcap.PcapStat;
import org.jnetpcap.constant.PcapDirection;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapTStampPrecision;
import org.jnetpcap.constant.PcapTstampType;
import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.util.PcapPacketRef;

import com.slytechs.jnet.jnetpcap.PacketHandler.OfBuffer;
import com.slytechs.jnet.jnetpcap.PacketHandler.OfForeign;
import com.slytechs.jnet.jnetpcap.PacketHandler.OfNative;
import com.slytechs.jnet.jnetpcap.PacketHandler.OfPacket;
import com.slytechs.jnet.jnetpcap.PacketHandler.OfPacketConsumer;
import com.slytechs.jnet.protocol.Packet;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public abstract sealed class BaseNetPcap
		implements PacketDispatcher
		permits NetPcap {

	private final NetPcap us = (NetPcap) this;

	private final Pcap pcap;

	protected BaseNetPcap(Pcap pcap) {
		this.pcap = pcap;
	}

	/**
	 * @throws PcapActivatedException
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#activate()
	 */
	public void activate() throws PcapActivatedException, PcapException {
		pcap.activate();
	}

	/**
	 * 
	 * @see org.jnetpcap.Pcap#breakloop()
	 */
	public void breakloop() {
		pcap.breakloop();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#canSetRfmon()
	 */
	public boolean canSetRfmon() throws PcapException {
		return pcap.canSetRfmon();
	}

	/**
	 * @param count
	 * @return
	 * @see com.slytechs.jnet.jnetpcap.PacketDispatcher#capturePackets(long)
	 */
	@Override
	public long capturePackets(long count) {
		return getPacketDispatcher().capturePackets(count);
	}

	/**
	 * 
	 * @see org.jnetpcap.Pcap#close()
	 */
	public void close() {
		pcap.close();
	}

	/**
	 * @param str
	 * @param optimize
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#compile(java.lang.String, boolean)
	 */
	public BpFilter compile(String str, boolean optimize) throws PcapException {
		return pcap.compile(str, optimize);
	}

	/**
	 * @param str
	 * @param optimize
	 * @param netmask
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#compile(java.lang.String, boolean, int)
	 */
	public BpFilter compile(String str, boolean optimize, int netmask) throws PcapException {
		return pcap.compile(str, optimize, netmask);
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#datalink()
	 */
	public PcapDlt datalink() throws PcapException {
		return pcap.datalink();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dataLinkExt()
	 */
	public PcapDlt dataLinkExt() throws PcapException {
		return pcap.dataLinkExt();
	}

	/**
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @see org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	protected int dispatch(int count, NativeCallback handler, MemorySegment user) {
		return pcap.dispatch(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapHandler.OfArray,
	 *      java.lang.Object)
	 */
	protected <U> int dispatch(int count, OfArray<U> handler, U user) throws PcapException {
		return pcap.dispatch(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dispatch(int,
	 *      org.jnetpcap.PcapHandler.OfMemorySegment, java.lang.Object)
	 */
	protected <U> int dispatch(int count, OfMemorySegment<U> handler, U user) throws PcapException {
		return pcap.dispatch(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param pcapDumper
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapDumper)
	 */
	protected <U> int dispatch(int count, PcapDumper pcapDumper) throws PcapException {
		return pcap.dispatch(count, pcapDumper);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param cb
	 * @param user
	 * @return
	 * @see com.slytechs.jnet.jnetpcap.PacketDispatcher#dispatchArray(int,
	 *      com.slytechs.jnet.jnetpcap.PacketHandler.OfArray, java.lang.Object)
	 */
	@Override
	public <U> int dispatchArray(int count, com.slytechs.jnet.jnetpcap.PacketHandler.OfArray<U> cb, U user) {
		return getPacketDispatcher().dispatchArray(count, cb, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param cb
	 * @param user
	 * @return
	 * @see com.slytechs.jnet.jnetpcap.PacketDispatcher#dispatchBuffer(int,
	 *      com.slytechs.jnet.jnetpcap.PacketHandler.OfBuffer, java.lang.Object)
	 */
	@Override
	public <U> int dispatchBuffer(int count, OfBuffer<U> cb, U user) {
		return getPacketDispatcher().dispatchBuffer(count, cb, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param memorySegmentHandler
	 * @param user
	 * @return
	 * @see com.slytechs.jnet.jnetpcap.PacketDispatcher#dispatchForeign(int,
	 *      com.slytechs.jnet.jnetpcap.PacketHandler.OfForeign, java.lang.Object)
	 */
	@Override
	public <U> int dispatchForeign(int count, OfForeign<U> memorySegmentHandler, U user) {
		return getPacketDispatcher().dispatchForeign(count, memorySegmentHandler, user);
	}

	/**
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @see com.slytechs.jnet.jnetpcap.PacketDispatcher#dispatchNative(int,
	 *      com.slytechs.jnet.jnetpcap.PacketHandler.OfNative,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int dispatchNative(int count, OfNative handler, MemorySegment user) {
		return getPacketDispatcher().dispatchNative(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param cb
	 * @param user
	 * @return
	 * @see com.slytechs.jnet.jnetpcap.PacketDispatcher#dispatchPacket(int,
	 *      com.slytechs.jnet.jnetpcap.PacketHandler.OfPacket, java.lang.Object)
	 */
	@Override
	public <U> int dispatchPacket(int count, OfPacket<U> cb, U user) {
		return getPacketDispatcher().dispatchPacket(count, cb, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param cb
	 * @param user
	 * @param packetFactory
	 * @return
	 * @see com.slytechs.jnet.jnetpcap.PacketDispatcher#dispatchPacket(int,
	 *      com.slytechs.jnet.jnetpcap.PacketHandler.OfPacket, java.lang.Object,
	 *      java.util.function.Supplier)
	 */
	@Override
	public <U> int dispatchPacket(int count, OfPacket<U> cb, U user, Supplier<Packet> packetFactory) {
		return getPacketDispatcher().dispatchPacket(count, cb, user, packetFactory);
	}

	/**
	 * @param <U>
	 * @param cb
	 * @return
	 * @see com.slytechs.jnet.jnetpcap.PacketDispatcher#dispatchPacket(com.slytechs.jnet.jnetpcap.PacketHandler.OfPacketConsumer)
	 */
	@Override
	public <U> int dispatchPacket(OfPacketConsumer cb) {
		return getPacketDispatcher().dispatchPacket(cb);
	}

	/**
	 * @param fname
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dumpOpen(java.lang.String)
	 */
	protected PcapDumper dumpOpen(String fname) throws PcapException {
		return pcap.dumpOpen(fname);
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.jnetpcap.PacketDispatcher#getDefaultPacket()
	 */
	@Override
	public Packet getDefaultPacket() {
		return getPacketDispatcher().getDefaultPacket();
	}

	/**
	 * @return
	 * @see org.jnetpcap.Pcap#geterr()
	 */
	protected String geterr() {
		return pcap.geterr();
	}

	/**
	 * @return
	 * @see org.jnetpcap.Pcap#getName()
	 */
	protected final String getName() {
		return pcap.getName();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#getNonBlock()
	 */
	protected boolean getNonBlock() throws PcapException {
		return pcap.getNonBlock();
	}

	protected abstract PacketDispatcher getPacketDispatcher();

	/**
	 * @return
	 * @see org.jnetpcap.Pcap#getPcapHeaderABI()
	 */
	protected PcapHeaderABI getPcapHeaderABI() {
		return pcap.getPcapHeaderABI();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#getTstampPrecision()
	 */
	public PcapTStampPrecision getTstampPrecision() throws PcapException {
		return pcap.getTstampPrecision();
	}

	/**
	 * @param array
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#inject(byte[])
	 */
	protected final int inject(byte[] array) throws PcapException {
		return pcap.inject(array);
	}

	/**
	 * @param array
	 * @param offset
	 * @param length
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#inject(byte[], int, int)
	 */
	protected final int inject(byte[] array, int offset, int length) throws PcapException {
		return pcap.inject(array, offset, length);
	}

	/**
	 * @param buf
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#inject(java.nio.ByteBuffer)
	 */
	protected final int inject(ByteBuffer buf) throws PcapException {
		return pcap.inject(buf);
	}

	/**
	 * @param packet
	 * @param length
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#inject(java.lang.foreign.MemorySegment, int)
	 */
	protected int inject(MemorySegment packet, int length) throws PcapException {
		return pcap.inject(packet, length);
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#isSwapped()
	 */
	protected boolean isSwapped() throws PcapException {
		return pcap.isSwapped();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#listDataLinks()
	 */
	protected List<PcapDlt> listDataLinks() throws PcapException {
		return pcap.listDataLinks();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#listTstampTypes()
	 */
	protected List<PcapTstampType> listTstampTypes() throws PcapException {
		return pcap.listTstampTypes();
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	protected <U> int loop(int count, NativeCallback handler, MemorySegment user) {
		return pcap.loop(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapHandler.OfArray,
	 *      java.lang.Object)
	 */
	protected <U> int loop(int count, OfArray<U> handler, U user) throws PcapException {
		return pcap.loop(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapHandler.OfMemorySegment,
	 *      java.lang.Object)
	 */
	protected <U> int loop(int count, OfMemorySegment<U> handler, U user) {
		return pcap.loop(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param pcapDumper
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapDumper)
	 */
	protected <U> int loop(int count, PcapDumper pcapDumper) throws PcapException {
		return pcap.loop(count, pcapDumper);
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#majorVersion()
	 */
	public int majorVersion() throws PcapException {
		return pcap.majorVersion();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#minorVersion()
	 */
	public int minorVersion() throws PcapException {
		return pcap.minorVersion();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#next()
	 */
	protected PcapPacketRef next() throws PcapException {
		return pcap.next();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @throws TimeoutException
	 * @see org.jnetpcap.Pcap#nextEx()
	 */
	protected PcapPacketRef nextEx() throws PcapException, TimeoutException {
		return pcap.nextEx();
	}

	/**
	 * @param packet
	 * @return
	 * @see com.slytechs.jnet.jnetpcap.PacketDispatcher#nextPacket(com.slytechs.jnet.protocol.Packet)
	 */
	@Override
	public boolean nextPacket(Packet packet) {
		return getPacketDispatcher().nextPacket(packet);
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#order()
	 */
	protected final ByteOrder order() throws PcapException {
		return pcap.order();
	}

	/**
	 * @param prefix
	 * @return
	 * @see org.jnetpcap.Pcap#perror(java.lang.String)
	 */
	public NetPcap perror(String prefix) {
		pcap.perror(prefix);

		return us;
	}

	/**
	 * @param buf
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#sendPacket(byte[])
	 */
	protected final void sendPacket(byte[] buf) throws PcapException {
		pcap.sendPacket(buf);
	}

	/**
	 * @param buf
	 * @param offset
	 * @param length
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#sendPacket(byte[], int, int)
	 */
	protected final void sendPacket(byte[] buf, int offset, int length) throws PcapException {
		pcap.sendPacket(buf, offset, length);
	}

	/**
	 * @param buf
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#sendPacket(java.nio.ByteBuffer)
	 */
	protected final void sendPacket(ByteBuffer buf) throws PcapException {
		pcap.sendPacket(buf);
	}

	/**
	 * @param packet
	 * @param length
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#sendPacket(java.lang.foreign.MemorySegment, int)
	 */
	protected void sendPacket(MemorySegment packet, int length) throws PcapException {
		pcap.sendPacket(packet, length);
	}

	/**
	 * @param bufferSize
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setBufferSize(int)
	 */
	public Pcap setBufferSize(int bufferSize) throws PcapException {
		return pcap.setBufferSize(bufferSize);
	}

	/**
	 * @param dlt
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDatalink(int)
	 */
	public NetPcap setDatalink(int dlt) throws PcapException {
		pcap.setDatalink(dlt);

		return us;
	}

	/**
	 * @param dlt
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDatalink(java.util.Optional)
	 */
	public NetPcap setDatalink(Optional<PcapDlt> dlt) throws PcapException {
		pcap.setDatalink(dlt);

		return us;
	}

	/**
	 * @param dlt
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDatalink(org.jnetpcap.constant.PcapDlt)
	 */
	public NetPcap setDatalink(PcapDlt dlt) throws PcapException {
		pcap.setDatalink(dlt);

		return us;
	}

	/**
	 * @param dir
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDirection(int)
	 */
	public NetPcap setDirection(int dir) throws PcapException {
		pcap.setDirection(dir);

		return us;
	}

	/**
	 * @param dir
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDirection(java.util.Optional)
	 */
	public NetPcap setDirection(Optional<PcapDirection> dir) throws PcapException {
		pcap.setDirection(dir);

		return us;
	}

	/**
	 * @param dir
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDirection(org.jnetpcap.constant.PcapDirection)
	 */
	public NetPcap setDirection(PcapDirection dir) throws PcapException {
		pcap.setDirection(dir);

		return us;
	}

	/**
	 * @param bpfProgram
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setFilter(org.jnetpcap.BpFilter)
	 */
	public NetPcap setFilter(BpFilter bpfProgram) throws PcapException {
		pcap.setFilter(bpfProgram);

		return us;
	}

	/**
	 * @param bpfProgram
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setFilter(java.util.Optional)
	 */
	public NetPcap setFilter(Optional<BpFilter> bpfProgram) throws PcapException {
		pcap.setFilter(bpfProgram);

		return us;
	}

	/**
	 * @param enable
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setImmediateMode(boolean)
	 */
	public NetPcap setImmediateMode(boolean enable) throws PcapException {
		pcap.setImmediateMode(enable);

		return us;
	}

	/**
	 * @param blockMode
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setNonBlock(boolean)
	 */
	public NetPcap setNonBlock(boolean blockMode) throws PcapException {
		pcap.setNonBlock(blockMode);

		return us;
	}

	/**
	 * @param promiscousMode
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setPromisc(boolean)
	 */
	public NetPcap setPromisc(boolean promiscousMode) throws PcapException {
		pcap.setPromisc(promiscousMode);

		return us;
	}

	/**
	 * @param rfMonitor
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setRfmon(boolean)
	 */
	public NetPcap setRfmon(boolean rfMonitor) throws PcapException {
		pcap.setRfmon(rfMonitor);

		return us;
	}

	/**
	 * @param snaplen
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setSnaplen(int)
	 */
	public NetPcap setSnaplen(int snaplen) throws PcapException {
		pcap.setSnaplen(snaplen);

		return us;
	}

	/**
	 * @param timeoutInMillis
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setTimeout(int)
	 */
	public NetPcap setTimeout(int timeoutInMillis) throws PcapException {
		pcap.setTimeout(timeoutInMillis);

		return us;
	}

	/**
	 * @param precision
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setTstampPrecision(org.jnetpcap.constant.PcapTStampPrecision)
	 */
	public NetPcap setTstampPrecision(PcapTStampPrecision precision) throws PcapException {
		pcap.setTstampPrecision(precision);

		return us;
	}

	/**
	 * @param type
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setTstampType(org.jnetpcap.constant.PcapTstampType)
	 */
	public NetPcap setTstampType(PcapTstampType type) throws PcapException {
		pcap.setTstampType(type);

		return us;
	}

	/**
	 * @param exceptionHandler
	 * @return
	 * @see org.jnetpcap.Pcap#setUncaughtExceptionHandler(java.util.function.Consumer)
	 */
	public NetPcap setUncaughtExceptionHandler(Consumer<? super Throwable> exceptionHandler) {
		pcap.setUncaughtExceptionHandler(exceptionHandler);

		return us;
	}

	/**
	 * @param exceptionHandler
	 * @return
	 * @see org.jnetpcap.Pcap#setUncaughtExceptionHandler(java.lang.Thread.UncaughtExceptionHandler)
	 */
	public NetPcap setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		pcap.setUncaughtExceptionHandler(exceptionHandler);

		return us;
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#snapshot()
	 */
	public int snapshot() throws PcapException {
		return pcap.snapshot();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#stats()
	 */
	public PcapStat stats() throws PcapException {
		return pcap.stats();
	}
}
