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
package com.slytechs.jnet.jnetpcap.internal.ipf;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.function.Consumer;

import com.slytechs.jnet.jnetpcap.internal.ipf.TimeoutQueue.Expirable;
import com.slytechs.jnet.jnetruntime.time.TimestampSource;
import com.slytechs.jnet.protocol.Registration;

/**
 * The Class TimeoutQueue.
 *
 * @param <E> the element type
 * @author Mark Bednarczyk
 */
public class TimeoutQueue<E extends Expirable> {

	/**
	 * The Interface Expirable.
	 *
	 * @author Mark Bednarczyk
	 */
	public interface Expirable {
		
		/**
		 * Expiration.
		 *
		 * @return the long
		 */
		long expiration();
	}

	/**
	 * The Class Entry.
	 *
	 * @author Mark Bednarczyk
	 */
	private class Entry implements Expirable {

		/** The e. */
		final E e;
		
		/** The action. */
		final Consumer<E> action;

		/**
		 * Instantiates a new entry.
		 *
		 * @param dst    the dst
		 * @param action the action
		 */
		public Entry(E dst, Consumer<E> action) {
			this.e = dst;
			this.action = action;

		}

		/**
		 * Do action.
		 */
		public void doAction() {
			action.accept(e);
		}

		/**
		 * Expiration.
		 *
		 * @return the long
		 * @see com.slytechs.jnet.jnetpcap.internal.ipf.TimeoutQueue.Expirable#expiration()
		 */
		@Override
		public long expiration() {
			return e.expiration();
		}
	}

	/** The queue. */
	private final BlockingQueue<Entry> queue;
	
	/** The time source. */
	private final TimestampSource timeSource;

	/**
	 * Instantiates a new timeout queue.
	 *
	 * @param size       the size
	 * @param timeSource the time source
	 */
	public TimeoutQueue(int size, TimestampSource timeSource) {
		this.timeSource = timeSource;
		this.queue = new PriorityBlockingQueue<>(size, (o1, o2) -> (int) (o1.expiration() - o2.expiration()));
	}

	/**
	 * Adds the.
	 *
	 * @param e      the e
	 * @param action the action
	 * @return the registration
	 */
	public Registration add(E e, Consumer<E> action) {

		queue.offer(new Entry(e, action));

		return () -> queue.remove(e);
	}

	/**
	 * Checks if is empty.
	 *
	 * @return true, if is empty
	 */
	public boolean isEmpty() {
		return queue.isEmpty();
	}
}
