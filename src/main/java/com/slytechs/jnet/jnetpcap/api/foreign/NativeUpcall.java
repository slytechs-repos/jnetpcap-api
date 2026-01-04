package com.slytechs.jnet.jnetpcap.api.foreign;

import java.lang.foreign.MemorySegment;

public interface NativeUpcall {

	public void nativeUpcall(MemorySegment user, MemorySegment header, MemorySegment packet);

	default void setUserCallback(NativeUpcall userCallback) {}
}