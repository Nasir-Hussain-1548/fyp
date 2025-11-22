use chrono::{DateTime, TimeZone, Utc};
use prost_types::Timestamp;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug)]
pub struct TimestampWrapper(pub Timestamp);

#[allow(dead_code)]
pub fn serialize<S>(value: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let dt = Utc
        .timestamp_opt(value.seconds, value.nanos as u32)
        .single()
        .ok_or_else(|| serde::ser::Error::custom("invalid timestamp"))?;
    dt.serialize(serializer)
}

#[allow(dead_code)]
pub fn deserialize<'de, D>(deserializer: D) -> Result<Timestamp, D::Error>
where
    D: Deserializer<'de>,
{
    let dt = DateTime::<Utc>::deserialize(deserializer)?;
    Ok(Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    })
}

pub trait IntoTimestamp {
    fn into_timestamp(self) -> Timestamp;
}

pub trait FromTimestamp {
    fn from_timestamp(ts: Timestamp) -> Self;
}

impl From<Timestamp> for TimestampWrapper {
    fn from(ts: Timestamp) -> Self {
        TimestampWrapper(ts)
    }
}

impl From<TimestampWrapper> for Timestamp {
    fn from(wrapper: TimestampWrapper) -> Self {
        wrapper.0
    }
}

impl Serialize for TimestampWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Timestamp", 2)?;
        state.serialize_field("seconds", &self.0.seconds)?;
        state.serialize_field("nanos", &self.0.nanos)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for TimestampWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            seconds: i64,
            nanos: i32,
        }
        let helper = Helper::deserialize(deserializer)?;
        Ok(TimestampWrapper(Timestamp {
            seconds: helper.seconds,
            nanos: helper.nanos,
        }))
    }
}

impl IntoTimestamp for TimestampWrapper {
    fn into_timestamp(self) -> Timestamp {
        self.0
    }
}

impl FromTimestamp for TimestampWrapper {
    fn from_timestamp(ts: Timestamp) -> Self {
        TimestampWrapper(ts)
    }
}

impl IntoTimestamp for Option<TimestampWrapper> {
    fn into_timestamp(self) -> Timestamp {
        self.map(|w| w.0).unwrap_or_default()
    }
}

impl FromTimestamp for Option<TimestampWrapper> {
    fn from_timestamp(ts: Timestamp) -> Self {
        Some(TimestampWrapper(ts))
    }
}

// Convenience helpers that are used elsewhere in the codebase
/// Return current time as seconds since UNIX epoch
pub fn now_seconds() -> i64 {
    Utc::now().timestamp()
}

/// Return current time as prost_types::Timestamp
pub fn now_prost() -> Timestamp {
    let dt = Utc::now();
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

pub mod option {
    use super::*;
    use chrono::Utc;
    use serde::{Deserialize, Deserializer, Serializer};
    #[allow(dead_code)]
    pub fn serialize<S>(timestamp: &Option<Timestamp>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match timestamp {
            Some(ts) => super::serialize(ts, serializer),
            None => serializer.serialize_none(),
        }
    }
    #[allow(dead_code)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Timestamp>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<DateTime<Utc>>::deserialize(deserializer)?;
        Ok(opt.map(|dt| Timestamp {
            seconds: dt.timestamp(),
            nanos: dt.timestamp_subsec_nanos() as i32,
        }))
    }
}
