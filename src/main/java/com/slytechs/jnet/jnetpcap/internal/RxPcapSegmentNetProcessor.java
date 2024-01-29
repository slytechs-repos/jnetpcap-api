package com.slytechs.jnet.jnetpcap.internal;

import java.lang.foreign.MemorySegment;

import org.jnetpcap.PcapHandler.OfMemorySegment;
import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnet.jnetruntime.pipeline.AbstractNetProcessor;
import com.slytechs.jnet.jnetruntime.pipeline.NetProcessor;
import com.slytechs.jnet.jnetruntime.pipeline.NetProcessorGroup;
import com.slytechs.jnet.jnetruntime.pipeline.NetProcessorType;

public abstract class RxPcapSegmentNetProcessor<T extends NetProcessor<T>> 
		extends AbstractNetProcessor<T> {
	
	private OfMemorySegment<Object> nextHandler;
	private RxPcapSegmentNetProcessor<?> nextProcessor;
	private PcapHeaderABI pcapAbi;

	public RxPcapSegmentNetProcessor(NetProcessorGroup group, int priority, NetProcessorType classifier) {
		super(group, priority, classifier);
	}
	
	protected final PcapHeaderABI pcapAbi() {
		return pcapAbi;
	}

	@Override
	public final OfMemorySegment<Object> sink() {
		return this::nextPacket;
	}

	protected abstract void nextPacket(Object u, MemorySegment hdr, MemorySegment pkt);
	
	protected final OfMemorySegment<Object> nextHandler() {
		return nextHandler;
	}

	@Override
	public void setup() {
		this.nextHandler = this.nextProcessor.sink();
	}

	@Override
	public void dispose() {
		this.nextHandler = null;
		this.nextProcessor = null;
	}

	@Override
	public final void link(NetProcessor<?> next) {

		switch(next) {
		case RxPcapSegmentNetProcessor<?> n -> this.nextProcessor = n;
		
		default -> 			throw new IllegalStateException("unsupported next processor type");
		}
	}

}
