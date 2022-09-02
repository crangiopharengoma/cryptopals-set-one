use std::time::Instant;

use reqwest::StatusCode;

use crate::encoding::hex::Hex;
use crate::mac::Hmac;

pub struct TimingAttack<T: Hmac> {
    url_structure: UrlStructure,
    hmac: T,
    hmac_found: bool,
}

pub struct UrlStructure {
    protocol: String,
    url: String,
    port: String,
    endpoint: String,
    arg_list: Option<Vec<(String, String)>>,
    hmac_param_name: String,
}

// This should probably have a builder but at the moment it's only used in one place with all the parameters
impl UrlStructure {
    pub fn new(
        protocol: String,
        url: String,
        port: String,
        endpoint: String,
        arg_list: Option<Vec<(String, String)>>,
        hmac_param_name: String,
    ) -> UrlStructure {
        UrlStructure {
            protocol,
            url,
            port,
            endpoint,
            arg_list,
            hmac_param_name,
        }
    }

    fn build(&self) -> String {
        if let Some(arg_list) = &self.arg_list {
            let args = arg_list
                .iter()
                .map(|(param, arg)| format!("{}={}", param, arg))
                .collect::<Vec<String>>()
                .join("&");
            format!(
                "{}://{}:{}/{}?{}&{}=",
                self.protocol, self.url, self.port, self.endpoint, args, self.hmac_param_name
            )
        } else {
            // "http://127.0.0.1:8080/challenge31?file={}&signature={}",
            format!(
                "{}://{}:{}/{}?{}=",
                self.protocol, self.url, self.port, self.endpoint, self.hmac_param_name
            )
        }
    }
}

impl<T: Hmac> TimingAttack<T> {
    pub fn new(url_structure: UrlStructure) -> TimingAttack<T> {
        TimingAttack {
            url_structure,
            hmac: T::default(),
            hmac_found: false,
        }
    }

    /// Returns Some(Hmac) if the timing attack has run successfully
    pub fn get_hmac(&self) -> Option<&T> {
        if self.hmac_found {
            Some(&self.hmac)
        } else {
            None
        }
    }

    /// Run the timing attack
    ///
    /// Sample size determines how many requests are sent for each possible hmac
    /// Lower values are more susceptible to network noise, but will run faster
    /// For a sample size 'n' if n = 0 1 request is sent, if n > 0 n requests are sent
    ///
    /// Batch size determines how many results are analysed at a time
    /// Lower batch sizes will run faster (because it won't search as far past the correct answer)
    /// Larger batch sizes will be more accurate as network noise etc may impact the standard deviation
    ///
    /// Sensitivity is the threshold for standard deviation - if SD is less than this amount the batch is ignored
    /// For challenge 31 this can be a relatively high value (I use 10) since the 50ms delay stands out relative to the other requests
    /// For challenge 32 this needs to be lower since the time taken to reject a request is a much smaller proportion of the total request time
    /// This increases the flexibility of sample size - e.g. challenge 31 can be run with a low sample size (to improve performance)
    /// and moderate sensitivity (to prevent slight variations in request handling time from producing a false positive)
    /// Negative values are accepted but have no meaningful difference from passing in 0.0
    pub fn run(&mut self, sample_size: usize, batch_size: usize, sensitivity: f64) -> bool {
        let url = self.url_structure.build();

        for pos in 0..20 {
            let mut batch = Vec::with_capacity(batch_size);
            'comp_loop: for hmac_component in 0..=u8::MAX {
                self.hmac[pos] = hmac_component;
                let hmac_hex = Hex::new(&self.hmac[..]);
                let url = format!("{}{}", url, hmac_hex);

                // Experimenting showed that the very first request was always slower than expected and this was a commmon source of false positives
                // I suspect this is environmental (e.g. reqwest doing some setup on first run maybe?), but to work around it, fire off a request
                // and don't measure it
                if pos == 0 && hmac_component == 0 {
                    reqwest::blocking::get(&url).unwrap();
                }

                let mut times = Vec::with_capacity(sample_size);
                let last_resp = loop {
                    let start = Instant::now();
                    let resp = reqwest::blocking::get(&url).unwrap();
                    times.push(start.elapsed());
                    if times.len() >= sample_size {
                        break resp;
                    }
                };

                let mean_finish = if sample_size > 1 {
                    times
                        .iter()
                        .fold(0, |acc, duration| acc + duration.as_millis())
                        / (sample_size as u128)
                } else {
                    times[0].as_millis()
                };

                match last_resp.status() {
                    StatusCode::OK => {
                        // println!("HMAC for {message} is {:?}", self.hmac);
                        self.hmac_found = true;
                        return true;
                    }
                    StatusCode::INTERNAL_SERVER_ERROR => {
                        batch.push((hmac_component, mean_finish as f64));
                        if batch.len() == batch_size || hmac_component == u8::MAX {
                            if let Some(found) = analyse_batch(batch, sensitivity) {
                                self.hmac[pos] = found;
                                break 'comp_loop;
                            } else {
                                batch = Vec::with_capacity(batch_size);
                            }
                        }
                    }
                    _ => {
                        println!(
                            "Something unexpected went wrong: {} - {}",
                            last_resp.status().as_str(),
                            last_resp
                                .text()
                                .unwrap_or_else(|_| String::from("No text in response"))
                        );
                    }
                }
            }
        }

        println!("failed to break hmac");
        false
    }
}

fn analyse_batch(batch: Vec<(u8, f64)>, sensitivity: f64) -> Option<u8> {
    println!("batch: {batch:?}");
    let batch_mean_duration = batch
        .iter()
        .fold(0f64, |acc, (_, mean_finish)| acc + mean_finish)
        / batch.len() as f64;

    let variance = batch.iter().fold(0f64, |acc, (_, mean_finish)| {
        acc + (batch_mean_duration - mean_finish).abs().powi(2)
    }) / batch.len() as f64;

    // // short circuit the analysis and return early if there's minimal variation within the batch
    // if variance < (batch_mean_duration * sensitivity) {
    //     return None;
    // }

    let standard_deviation = (variance as f64).sqrt();
    println!("batch average: {batch_mean_duration} variance: {variance} sd: {standard_deviation}");

    if standard_deviation < sensitivity {
        return None;
    }

    for (hmac_component, mean_request_duration) in batch.into_iter() {
        // usually this would be an absolute value, but if it's faster than average
        // we're not interested - we are looking for slower than usual request durations
        let distance = mean_request_duration - batch_mean_duration;
        println!("value: {hmac_component} distance: {distance} threshold: {standard_deviation}");
        if distance > standard_deviation {
            println!("That's a success - next hmac value is {hmac_component}");
            return Some(hmac_component);
        }
    }
    None
}
