use std::collections::BTreeMap;
use std::time::Instant;

const LBOUND: f64 = 1.0;
const UBOUND: f64 = 60.0;
const ALPHA: f64 = 0.8;
const BETA: f64 = 1.6;

#[derive(Debug, Clone)]
pub struct Timers {
    on_flight: BTreeMap<u32, Instant>,
    srtt: f64,
    rto: f64,
}

impl Timers {
    pub fn default() -> Timers {
        Timers {
            on_flight: BTreeMap::new(),
            srtt: LBOUND,
            rto: LBOUND,
        }
    }

    pub fn on_send(&mut self, seq: u32) {
        if let Some((&max_seq, _)) = self.on_flight.last_key_value()
            && max_seq >= seq
        {
            return;
        }
        self.on_flight.insert(seq, Instant::now());
    }

    pub fn on_ack(&mut self, ack_no: u32) {
        if let Some((&first_seq_no, time)) = self.on_flight.first_key_value()
            && first_seq_no < ack_no
        {
            self.calculate_srtt(*time);
        }
        self.on_flight = self.on_flight.split_off(&ack_no);
    }

    /// Measure the elapsed time between sending a data octet with a
    /// particular sequence number and receiving an acknowledgment that
    /// covers that sequence number (segments sent do not have to match
    /// segments received).  This measured elapsed time is the Round Trip
    /// Time (RTT).  Next compute a Smoothed Round Trip Time (SRTT) as:
    ///
    /// SRTT = ( ALPHA * SRTT ) + ((1-ALPHA) * RTT)
    ///
    /// and based on this, compute the retransmission timeout (RTO) as:
    ///
    /// RTO = min[UBOUND,max[LBOUND,(BETA*SRTT)]]
    ///
    /// where UBOUND is an upper bound on the timeout (e.g., 1 minute),
    /// LBOUND is a lower bound on the timeout (e.g., 1 second), ALPHA is
    /// a smoothing factor (e.g., .8 to .9), and BETA is a delay variance
    /// factor (e.g., 1.3 to 2.0).
    fn calculate_srtt(&mut self, time: Instant) {
        let rtt = time.elapsed().as_secs_f64();
        let srtt = ALPHA * self.srtt + (1.0 - ALPHA) * rtt;
        self.srtt = srtt;
        self.rto = UBOUND.min(LBOUND.max(BETA * srtt));
    }

    pub fn is_retransmit(&self) -> bool {
        self.on_flight
            .first_key_value()
            .is_some_and(|(&_, time)| time.elapsed().as_secs_f64() >= self.rto)
    }
}
