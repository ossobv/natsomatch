use std::time::{Duration, Instant};


pub struct Stats {
    t0: Instant,
    tlatest: Instant,
    count: u64,
    prepare_t: Duration,
    publish_t: Duration,
}

impl Stats {
    pub fn default() -> Stats {
        Stats{
            t0: Instant::now(),
            tlatest: Instant::now(),
            count: 0,
            prepare_t: Duration::default(),
            publish_t: Duration::default(),
        }
    }

    pub fn get_count(&self) -> u64 {
        self.count
    }

    pub fn get_last_publish(&self) -> u64 {
        self.tlatest.elapsed().as_secs()
    }

    pub fn reset(&mut self) -> &Stats {
        // FIXME: dupe code with default()?
        self.t0 = Instant::now();
        self.count = 0;
        self.prepare_t = Duration::default();
        self.publish_t = Duration::default();
        self
    }

    pub fn inc(&mut self, prepare_t: Duration, publish_t: Duration) -> &Stats {
        self.tlatest = Instant::now();
        self.count += 1;
        self.prepare_t += prepare_t;
        self.publish_t += publish_t;
        self
    }

    pub fn as_json(&self) -> String {
        format!(
            r#"{{"runtime":{},"processed":{},"last_publish_at":{}}}"#,
            self.t0.elapsed().as_secs(), self.get_count(), self.get_last_publish())
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let elapsed = self.t0.elapsed().as_secs();
        let msg_per_sec: f32 = (self.count as f32) / (elapsed as f32);
        let prep_us_per_msg: f32;
        let pub_us_per_msg: f32;
        if self.count > 0 {
            prep_us_per_msg = (self.prepare_t.as_micros() as f32) / (self.count as f32);
            pub_us_per_msg = (self.publish_t.as_micros() as f32) / (self.count as f32);
        } else {
            prep_us_per_msg = 0.0;
            pub_us_per_msg = 0.0;
        }
        write!(
            f, "{}s {}x {:.1}x/s {:.3}µs/prep {:.3}µs/pub",
            elapsed, self.count, msg_per_sec, prep_us_per_msg, pub_us_per_msg)
    }
}
