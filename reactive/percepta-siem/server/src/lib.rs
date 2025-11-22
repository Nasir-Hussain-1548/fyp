use prost_types::Timestamp;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Provide serde helper modules expected by generated protobuf code.
/// Generated code references `crate::timestamps::option` for Option<Timestamp>.
pub mod timestamps {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub mod option {
        use super::*;

        #[allow(dead_code)]
        pub fn serialize<S>(timestamp: &Option<Timestamp>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match timestamp {
                Some(ts) => {
                    let unix_ts = SystemTime::UNIX_EPOCH
                        + std::time::Duration::new(ts.seconds as u64, ts.nanos as u32);
                    unix_ts
                        .duration_since(UNIX_EPOCH)
                        .map_err(serde::ser::Error::custom)?
                        .as_secs()
                        .serialize(serializer)
                }
                None => serializer.serialize_none(),
            }
        }

        #[allow(dead_code)]
        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Timestamp>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let seconds: Option<i64> = Option::deserialize(deserializer)?;
            Ok(seconds.map(|secs| Timestamp {
                seconds: secs,
                nanos: 0,
            }))
        }
    }

    pub mod ts {
        use super::*;

        #[allow(dead_code)]
        pub fn serialize<S>(timestamp: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let unix_ts = SystemTime::UNIX_EPOCH
                + std::time::Duration::new(timestamp.seconds as u64, timestamp.nanos as u32);
            unix_ts
                .duration_since(UNIX_EPOCH)
                .map_err(serde::ser::Error::custom)?
                .as_secs()
                .serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Timestamp, D::Error>
        where
            D: Deserializer<'de>,
        {
            let seconds: i64 = i64::deserialize(deserializer)?;
            Ok(Timestamp { seconds, nanos: 0 })
        }
    }
}

// Export core modules
pub mod alerts;
pub mod rule_engine;

// Generated protobuf definitions for use in library modules
pub mod percepta {
    tonic::include_proto!("percepta.siem.ingestion.v1");
}
