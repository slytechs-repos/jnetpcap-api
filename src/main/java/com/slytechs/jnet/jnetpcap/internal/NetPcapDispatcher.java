package com.slytechs.jnet.jnetpcap.internal;

import java.lang.foreign.MemorySegment;

import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.internal.PcapHeaderABI;

import com.slytechs.jnet.jnetruntime.pipeline.NetProcessorGroup;
import com.slytechs.jnet.jnetruntime.pipeline.NetProcessorType;

public class NetPcapDispatcher extends RxPcapSegmentNetProcessor<NetPcapDispatcher> {

	private final PcapDispatcher dispatcher;
	private final PcapHeaderABI pcapAbi;
	
	protected NetPcapDispatcher(NetProcessorGroup group, int priority, PcapDispatcher dispatcher, PcapHeaderABI pcapAbi) {
		super(group, priority, NetProcessorType.RX_PCAP_RAW);
		this.dispatcher = dispatcher;
		this.pcapAbi = pcapAbi;
	}

	@Override
	public void setup() {
		super.setup();
	}

	@Override
	public void dispose() {
		super.dispose();
	}

	@Override
	protected void nextPacket(Object u, MemorySegment hdr, MemorySegment pkt) {
		
	}

}
