package de.devsurf.security.otp.api;

import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

public class Clock {

	protected int interval;
	protected Calendar calendar;

	public Clock() {
		this(30);
	}

	public Clock(int interval) {
		this.interval = interval;
		calendar = GregorianCalendar.getInstance(TimeZone.getTimeZone("UTC"));
	}

	public long getCurrentSeconds() {
		return calendar.getTimeInMillis() / 1000;
	}

	public long getCurrentInterval() {
		return getCurrentSeconds() / interval;
	}

	public static class ExactClock extends Clock {
		public ExactClock() {
			super();
		}

		public ExactClock(int interval) {
			super(interval);
		}

		public long getCurrentSeconds() {
			return System.currentTimeMillis() / 1000;
		}
	}
	
	public static class StaticClock extends Clock {
		private long millis;
		public StaticClock(long millis) {
			super();
			this.millis = millis;
		}

		public StaticClock(long millis, int interval) {
			super(interval);
			this.millis = millis;
		}

		public long getCurrentSeconds() {
			return millis / 1000;
		}
	}
}
