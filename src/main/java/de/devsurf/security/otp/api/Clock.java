/*
Copyright 2013 Daniel Manzke (devsurf)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */
package de.devsurf.security.otp.api;

import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

public class Clock {

    protected int interval;

    protected Calendar calendar;

    public Clock() {
        this( 30 );
    }

    public Clock( int interval ) {
        this.interval = interval;
        calendar = GregorianCalendar.getInstance( TimeZone.getTimeZone( "UTC" ) );
    }

    public long getCurrentSeconds() {
        return calendar.getTimeInMillis() / 1000;
    }

    public long getCurrentInterval() {
        return getCurrentSeconds() / interval;
    }

    public static class ExactClock
        extends Clock {
        public ExactClock() {
            super();
        }

        public ExactClock( int interval ) {
            super( interval );
        }

        public long getCurrentSeconds() {
            return System.currentTimeMillis() / 1000;
        }
    }

    public static class StaticClock
        extends Clock {
        private long millis;

        public StaticClock( long millis ) {
            super();
            this.millis = millis;
        }

        public StaticClock( long millis, int interval ) {
            super( interval );
            this.millis = millis;
        }

        public long getCurrentSeconds() {
            return millis / 1000;
        }
    }
}
