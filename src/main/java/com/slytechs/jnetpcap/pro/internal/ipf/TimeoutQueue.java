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
package com.slytechs.jnetpcap.pro.internal.ipf;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.function.Consumer;

import com.slytechs.jnetpcap.pro.internal.ipf.TimeoutQueue.Expirable;
import com.slytechs.protocol.Registration;
import com.slytechs.protocol.runtime.time.TimestampSource;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class TimeoutQueue<E extends Expirable> {

	public interface Expirable extends Comparable<Long> {

	}

	private class Entry implements Expirable {

		final E e;
		final Consumer<E> action;

		public Entry(E dst, Consumer<E> action) {
			this.e = dst;
			this.action = action;

		}

		/**
		 * @see java.lang.Comparable#compareTo(java.lang.Object)
		 */
		@Override
		public int compareTo(Long o) {
			return e.compareTo(o);
		}

		public void doAction() {
			action.accept(e);
		}
	}

	private final BlockingQueue<Entry> queue;
	private final TimestampSource timeSource;

	public TimeoutQueue(int size, TimestampSource timeSource) {
		this.timeSource = timeSource;
		this.queue = new PriorityBlockingQueue<>(size);
	}

	public Registration add(E e, Consumer<E> action) {

		queue.offer(new Entry(e, action));

		return () -> queue.remove(e);
	}

	public boolean isEmpty() {
		return queue.isEmpty();
	}
}
