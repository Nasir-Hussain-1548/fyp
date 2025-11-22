use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use prost_types::Timestamp;

pub fn serialize<S>(timestamp: &Option<Timestamp>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match timestamp {
        Some(ts) => {
            let dt = Utc.timestamp_opt(ts.seconds, ts.nanos as u32)
                .single()
                .ok_or_else(|| serde::ser::Error::custom("invalid timestamp"))?;
            dt.serialize(serializer)
        }
        None => serializer.serialize_none(),
    }
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Timestamp>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<DateTime<Utc>> = Option::deserialize(deserializer)?;
    Ok(opt.map(|dt| Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }))
}